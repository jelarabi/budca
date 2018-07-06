#!/usr/bin/python

# libraries you import here, must be present on the target node.
import os, requests, json, sys, ast
from requests_toolbelt import MultipartEncoder

# Recovery of necessaary variables

def main():
    module = AnsibleModule(
        argument_spec = dict(
           ip_centreon = dict(required=True),
           headers = dict(required=True),
           hostname = dict(required=True),
           password = dict(required=True),
           user = dict(required=True),
        ),
        supports_check_mode = False,
    )

# Implementation of the parameters

    ip_centreon = module.params['ip_centreon']
    headers = ast.literal_eval(module.params['headers'])
    hostname = module.params['hostname']
    password = module.params['password']
    user = module.params['user']

    m = MultipartEncoder(fields={'username': user, 'password': password})

    r = requests.post('http://%s/centreon/api/index.php?action=authenticate' % ip_centreon, data=m, headers={'Content-Type': m.content_type})
    if r.status_code != 200:
        module.fail_json(msg='Failed to authenticate with centreon')

    body = json.loads(r.text)

# Add this token in Header
    tok = str(body['authToken'])
    headers['centreon-auth-token']=tok

#Request to delete Host in centreon with json body

    payload = json.dumps({"action": "del","object": "host","values": hostname})
    r = requests.post('http://%s/centreon/api/index.php?action=action&object=centreon_clapi' % ip_centreon, data=payload, headers=headers)
    if r.status_code == 404:
        module.fail_json(msg='Serveur hostname not found')
    if r.status_code == 401:
        module.fail_json(msg='Error with token Unauthorized')
    if r.status_code != 200:
        module.fail_json(msg='Failed to delete host in Centreon')

# Launch of API request who update poller Centreon configuration

    payload_poller = {'action': 'applycfg', 'values': '1'}

    r = requests.post('http://%s/centreon/api/index.php?action=action&object=centreon_clapi' % ip_centreon, headers=headers, json=payload_poller)

    if r.status_code != 500:
        module.fail_json(msg='Failed to re-generate the poller Local')
    body = r.status_code

    module.exit_json(changed=True,result=body)

# import module snippets (must stay here after your code)
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
