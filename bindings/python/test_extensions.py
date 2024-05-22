# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import json
import pytest
import regorus

TEST_EXT_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


@pytest.fixture(name="engine", scope="function")
def engine_fixture():
    """
    Fixture to handle creation and cleanup of a default policy engine.
    New engine is created for each test case.
    """
    engine = regorus.Engine()
    engine.add_policy_from_file('../../examples/extension_list/agent_extension_policy.rego')
    yield engine


@pytest.fixture(name="input_data")
def input_data_fixture():
    """
    Fixture to handle creation and cleanup of a default input data.
    New input data is created for each test case.
    """
    input_data = {
        "extensions": {
            TEST_EXT_NAME: {
                "signingInfo": {
                    "extensionSigned": False
                }
            }
        }
    }
    input_json = json.dumps(input_data)
    yield input_json


def test_default_data_json(engine, input_data):
    """Test the default data in json format for extension policy."""
    data_json = {
        "azureGuestAgentPolicy": {
            "policyVersion": "0.1.0",
            "signingRules": {
                "extensionSigned": False
            },
            "allowListOnly": False
        }
    }
    data_json = json.dumps(data_json)
    engine.add_data_json(data_json)
    engine.set_input_json(input_data)
    # Eval query
    results = engine.eval_query('data.agent_extension_policy')
    assert results['result'][0]['expressions'][0]['value']['extensions_to_download'][TEST_EXT_NAME]['downloadAllowed']


def test_default_data_file(engine, input_data):
    """Test the default data in file format for extension policy."""
    data_default_path = "../../examples/extension_list/agent-extension-default-data.json"
    engine.add_data_from_json_file(data_default_path)
    engine.set_input_json(input_data)
    # Eval query
    results = engine.eval_query('data.agent_extension_policy')
    assert results['result'][0]['expressions'][0]['value']['extensions_to_download'][TEST_EXT_NAME]['downloadAllowed']


def test_allow_all(engine, input_data):
    """Test the policy engine with allow all policy."""
    data_json = {
        "azureGuestAgentPolicy": {
            "policyVersion": "0.1.0",
            "signingRules": {
                "extensionSigned": False
            },
            "allowListOnly": False
        }
    }
    data_json = json.dumps(data_json)
    engine.add_data_json(data_json)
    engine.set_input_json(input_data)
    # Eval query
    results = engine.eval_query('data.agent_extension_policy')
    assert results['result'][0]['expressions'][0]['value']['extensions_to_download'][TEST_EXT_NAME]['downloadAllowed']


def test_allow_signed(engine):
    """Allow only signed extensions"""
    data_json = {
        "azureGuestAgentPolicy": {
            "policyVersion": "0.1.0",
            "signingRules": {
                "extensionSigned": True
            },
            "allowListOnly": False
        }
    }
    data_json = json.dumps(data_json)
    engine.add_data_json(data_json)
    input_data = {
        "extensions": {
            TEST_EXT_NAME: {
                "signingInfo": {
                    "extensionSigned": True
                }
            },
            TEST_EXT_NAME + "2": {
                "signingInfo": {
                    "extensionSigned": False
                }
            }
        }
    }
    input_data = json.dumps(input_data)
    engine.set_input_json(input_data)
    # Eval query
    results = engine.eval_query('data.agent_extension_policy')
    print(results)
    print(input_data)
    assert results['result'][0]['expressions'][0]['value']['extensions_validated'][TEST_EXT_NAME]['signingValidated']
    assert not results['result'][0]['expressions'][0]['value']['extensions_validated'][TEST_EXT_NAME + "2"]['signingValidated']
