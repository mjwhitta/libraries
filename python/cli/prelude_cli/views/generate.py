import json
import os

import click
from rich import print_json

from prelude_cli.views.shared import handle_api_error, Spinner
from prelude_sdk.controllers.generate_controller import GenerateController


@click.group()
@click.pass_context
def generate(ctx):
    """ Generate tests """
    ctx.obj = GenerateController(account=ctx.obj)


@generate.command('threat-intel')
@click.argument('threat_pdf', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.argument('output_dir', type=click.Path(dir_okay=True, file_okay=False, writable=True))
@click.pass_obj
@handle_api_error
def generate_threat_intel(controller: GenerateController, threat_pdf: str, output_dir: str):
    with Spinner('Uploading') as spinner:
        job_id = controller.upload_threat_intel(threat_pdf)['job_id']
        spinner.update(spinner.task_ids[-1], description='Parsing PDF')
        while (result := controller.get_threat_intel(job_id)) and result['status'] == 'RUNNING':
            if result['step'] == 'GENERATE':
                spinner.update(
                    spinner.task_ids[-1],
                    description=f'Generating ({result["completed_tasks"]}/{result["num_tasks"]})')
    if result['status'] == 'COMPLETE':
        for technique in result['output']:
            if technique['status'] == 'SUCCEEDED':
                technique_filename = technique['technique'].replace('.', '_')
                os.makedirs(f'{output_dir}/{technique_filename}')
                with open(f'{output_dir}/{technique_filename}/test.go', 'w') as f:
                    f.write(technique['go_code'])
                with open(f'{output_dir}/{technique_filename}/ioa.yaml', 'w') as f:
                    f.write(technique['ioa_yaml'])
                with open(f'{output_dir}/{technique_filename}/config.json', 'w') as f:
                    json.dump(dict(
                        technique=technique['technique'],
                        name=technique['name'],
                        unit='response',
                    ), f, indent=4)
        print_json(data=dict(
            output_dir=output_dir,
            successfully_generated=[t['technique'] for t in result['output'] if t['status'] == 'SUCCEEDED'],
            failed=[t['technique'] for t in result['output'] if t['status'] == 'FAILED'],
            job_id=job_id,
        ))
    else:
        raise Exception('Failed to generate threat intel: %s (ref: %s)', result['reason'], job_id)
