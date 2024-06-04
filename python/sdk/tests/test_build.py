import json
import os
import pytest
import time
from datetime import datetime, timedelta, timezone
from importlib.resources import files

from dateutil.parser import parse

from prelude_sdk.controllers.build_controller import BuildController
from prelude_sdk.controllers.detect_controller import DetectController

import templates
from testutils import *


@pytest.mark.order(2)
@pytest.mark.usefixtures('setup_account', 'setup_test')
class TestVST:

    def setup_class(self):
        self.build = BuildController(pytest.account)
        self.detect = DetectController(pytest.account)

    def test_create_test(self):
        expected = dict(
            account_id=pytest.account.headers['account'],
            author=pytest.expected_account['whoami'],
            id=pytest.test_id,
            name='test_name',
            unit='custom',
            technique=None,
            attachments=[],
            tombstoned=None
        )

        diffs = check_dict_items(expected, pytest.expected_test)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_upload(self, unwrap):
        def wait_for_compile(job_id):
            timeout = time.time() + 60
            while time.time() < timeout:
                time.sleep(5)
                res = unwrap(self.build.get_compile_status)(self.build, job_id=job_id)
                if res['status'] != 'RUNNING':
                    break
            return res

        template = files(templates).joinpath('template.go').read_text()
        res = unwrap(self.build.upload)(self.build, test_id=pytest.test_id, filename=f'{pytest.test_id}.go',
                                        data=template.encode("utf-8"))
        pytest.expected_test['attachments'].append(res['filename'])

        expected = dict(
            compile_job_id=res['compile_job_id'],
            filename=f'{pytest.test_id}.go',
            id=pytest.test_id,
        )
        assert expected == res

        assert res.get('compile_job_id') is not None
        res = wait_for_compile(res['compile_job_id'])
        per_platform_res = res.pop('results')
        assert 'COMPLETE' == res['status']
        assert 5 == len(per_platform_res)
        for platform in per_platform_res:
            assert 'SUCCEEDED' == platform['status']

    def test_get_test(self, unwrap):
        for suffix in ['darwin-arm64', 'darwin-x86_64', 'linux-arm64', 'linux-x86_64', 'windows-x86_64']:
            pytest.expected_test['attachments'].append(f'{pytest.test_id}_{suffix}')
        res = unwrap(self.detect.get_test)(self.detect, test_id=pytest.test_id)

        diffs = check_dict_items(pytest.expected_test, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_list_tests(self, unwrap):
        res = unwrap(self.detect.list_tests)(self.detect)
        owners = set([r['account_id'] for r in res])
        assert {'prelude', pytest.account.headers['account']} >= owners

        mine = [r for r in res if r['id'] == pytest.expected_test['id']]
        assert 1 == len(mine)
        del pytest.expected_test['attachments']
        diffs = check_dict_items(pytest.expected_test, mine[0])
        assert not diffs, json.dumps(diffs, indent=2)

    def test_update_test(self, unwrap):
        updated_name = 'updated_test'
        res = unwrap(self.build.update_test)(self.build, test_id=pytest.test_id, name=updated_name, technique='T1234.001')

        pytest.expected_test['name'] = updated_name
        pytest.expected_test['technique'] = 'T1234.001'

        diffs = check_dict_items(pytest.expected_test, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_download(self, unwrap):
        filename = f'{pytest.test_id}.go'
        res = unwrap(self.detect.download)(self.detect, test_id=pytest.test_id, filename=filename)
        assert res is not None
        with open(filename, 'wb') as f:
            f.write(res)
        assert os.path.isfile(filename)
        os.remove(filename)

    @pytest.mark.order(-2)
    def test_delete_test(self, unwrap):
        unwrap(self.build.delete_test)(self.build, test_id=pytest.test_id, purge=False)
        res = unwrap(self.detect.get_test)(self.detect, test_id=pytest.test_id)
        pytest.expected_test['tombstoned'] = res['tombstoned']

        diffs = check_dict_items(pytest.expected_test, res)
        assert not diffs, json.dumps(diffs, indent=2)
        assert parse(res['tombstoned']).replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc) + timedelta(minutes=1)

        unwrap(self.build.delete_test)(self.build, test_id=pytest.test_id, purge=True)
        with pytest.raises(Exception):
            unwrap(self.detect.get_test)(self.detect, test_id=pytest.test_id)


@pytest.mark.order(3)
@pytest.mark.usefixtures('setup_account', 'setup_test', 'setup_threat')
class TestThreat:

    def setup_class(self):
        self.build = BuildController(pytest.account)
        self.detect = DetectController(pytest.account)

    def test_create_threat(self):
        expected = dict(
            account_id=pytest.account.headers['account'],
            author=pytest.expected_account['whoami'],
            id=pytest.threat_id,
            source_id='aa23-061a',
            name='threat_name',
            source='https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a',
            published='2023-11-13',
            tests=['881f9052-fb52-4daf-9ad2-0a7ad9615baf', 'b74ad239-2ddd-4b1e-b608-8397a43c7c54', pytest.test_id],
            tombstoned=None
        )

        diffs = check_dict_items(expected, pytest.expected_threat)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_get_threat(self, unwrap):
        res = unwrap(self.detect.get_threat)(self.detect, threat_id=pytest.threat_id)

        diffs = check_dict_items(pytest.expected_threat, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_list_threats(self, unwrap):
        res = unwrap(self.detect.list_threats)(self.detect)
        owners = set([r['account_id'] for r in res])
        assert {'prelude', pytest.account.headers['account']} >= owners

        mine = [r for r in res if r['id'] == pytest.expected_threat['id']]
        assert 1 == len(mine)
        diffs = check_dict_items(pytest.expected_threat, mine[0])
        assert not diffs, json.dumps(diffs, indent=2)

    def test_update_threat(self, unwrap):
        updated_name = 'updated-threat'
        updated_tests = ['881f9052-fb52-4daf-9ad2-0a7ad9615baf', '74077d3b-6a2f-49fa-903e-99cad6f34cf6', 'b74ad239-2ddd-4b1e-b608-8397a43c7c54']
        res = unwrap(self.build.update_threat)(self.build, threat_id=pytest.threat_id, name=updated_name, source='',
                                               tests=','.join(updated_tests))

        pytest.expected_threat['name'] = updated_name
        pytest.expected_threat['source'] = None
        pytest.expected_threat['tests'] = updated_tests

        diffs = check_dict_items(pytest.expected_threat, res)
        assert not diffs, json.dumps(diffs, indent=2)

    @pytest.mark.order(-3)
    def test_delete_threat(self, unwrap):
        unwrap(self.build.delete_threat)(self.build, threat_id=pytest.threat_id, purge=False)
        res = unwrap(self.detect.get_threat)(self.detect, threat_id=pytest.threat_id)
        pytest.expected_threat['tombstoned'] = res['tombstoned']

        diffs = check_dict_items(pytest.expected_threat, res)
        assert not diffs, json.dumps(diffs, indent=2)
        assert parse(res['tombstoned']).replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc) + timedelta(minutes=1)

        unwrap(self.build.delete_threat)(self.build, threat_id=pytest.threat_id, purge=True)
        with pytest.raises(Exception):
            unwrap(self.detect.get_threat)(self.detect, threat_id=pytest.threat_id)


@pytest.mark.order(4)
@pytest.mark.usefixtures('setup_account', 'setup_test', 'setup_detection')
class TestDetection:

    def setup_class(self):
        if not pytest.expected_account['features']['detections']:
            pytest.skip("DETECTIONS feature not enabled")

        self.build = BuildController(pytest.account)
        self.detect = DetectController(pytest.account)

    def test_create_detection(self, unwrap):
        expected = dict(
            account_id=pytest.account.headers['account'],
            id=pytest.detection_id,
            name='Suspicious Command Line Usage in Windows',
            rule=dict(
                title='Suspicious Command Line Usage in Windows',
                description='Detects suspicious use of cmd.exe or powershell.exe with commands often used for reconnaissance like directory listing, tree viewing, or searching for sensitive files.',
                logsource=dict(category='process_creation', product='windows'),
                detection=dict(condition='selection', selection=dict(ParentImage='cmd.exe')),
                level='medium'
            ),
            rule_id=pytest.expected_detection['rule_id'],
            test=pytest.test_id
        )

        diffs = check_dict_items(expected, pytest.expected_detection)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_get_detection(self, unwrap):
        res = unwrap(self.detect.get_detection)(self.detect, detection_id=pytest.detection_id)

        diffs = check_dict_items(pytest.expected_detection, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_list_detections(self, unwrap):
        res = unwrap(self.detect.list_detections)(self.detect)
        owners = set([r['account_id'] for r in res])
        assert {'prelude', pytest.account.headers['account']} >= owners

        mine = [r for r in res if r['id'] == pytest.expected_detection['id']]
        assert 1 == len(mine)
        diffs = check_dict_items(pytest.expected_detection, mine[0])
        assert not diffs, json.dumps(diffs, indent=2)

    def test_update_detection(self, unwrap):
        updated_rule = pytest.detection_rule.replace(pytest.expected_detection['rule']['title'], 'Suspicious no more')
        res = unwrap(self.build.update_detection)(self.build, detection_id=pytest.detection_id, rule=updated_rule)
        pytest.expected_detection['rule']['title'] = 'Suspicious no more'

        diffs = check_dict_items(pytest.expected_detection, res)
        assert not diffs, json.dumps(diffs, indent=2)

    @pytest.mark.order(-4)
    def test_delete_detection(self, unwrap):
        unwrap(self.build.delete_detection)(self.build, detection_id=pytest.detection_id)
        with pytest.raises(Exception):
            unwrap(self.detect.get_detection)(self.detect, detection_id=pytest.detection_id)