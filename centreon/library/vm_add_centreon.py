#!/usr/bin/python

# libraries you import here, must be present on the target node.
import os, requests, json, sys, ast
from requests_toolbelt import MultipartEncoder

def main():
    module = AnsibleModule(
        argument_spec = dict(
           ip_centreon = dict(required=True),
           headers = dict(required=True),
           hostname = dict(required=True),
           ip = dict(required=True),
           password = dict(required=True),
           user = dict(required=True),
           os = dict(required=True),
        ),
        supports_check_mode = False,
    )

    ip_centreon = module.params['ip_centreon']
    headers = ast.literal_eval(module.params['headers'])   
    hostname = module.params['hostname']
    ip = module.params['ip']
    password = module.params['password']
    user = module.params['user']
    os = module.params['os']

    m = MultipartEncoder(fields={'username': user, 'password': password})

    if "windows" in os:
        os = "windows"
    else:
        os = "linux"

    r = requests.post('http://%s/centreon/api/index.php?action=authenticate' % ip_centreon, data=m, headers={'Content-Type': m.content_type})
    if r.status_code != 200:
        module.fail_json(msg='Failed to authenticate with centreon')

    body = json.loads(r.text)

# Add this token in Header

    tok = body['authToken']
    headers['centreon-auth-token']=tok

# Add host in hostgroup

    payload_host = {"action": "add", "object": "host", "values": "%s;%s;%s;%s-servers;central;%s" % (hostname, hostname, ip, os, os)}

    r = requests.post('http://%s/centreon/api/index.php?action=action&object=centreon_clapi' % ip_centreon, headers=headers, json=payload_host)
    if r.status_code == 409:
        module.fail_json(msg='Serveur hostname already exist')
    if r.status_code == 401:
        module.fail_json(msg='Error with token Unauthorized')
    if r.status_code != 200:
        module.fail_json(msg='Failed to add host in Centreon')

    body = json.loads(r.text)

# Launch of API request who update poller Centreon configuration 

    payload_poller = {'action': 'applycfg', 'values': '1'}

    r = requests.post('http://%s/centreon/api/index.php?action=action&object=centreon_clapi' % ip_centreon, headers=headers, json=payload_poller)

    if r.status_code != 500:
        module.fail_json(msg='Failed to re-generate the poller Local')
    body = r.status_code    

    payload_poller2 = {'action': 'pollertest', 'values': '1'}

    r = requests.post('http://%s/centreon/api/index.php?action=action&object=centreon_clapi' % ip_centreon, headers=headers, json=payload_poller2)

    if r.status_code != 200:
        module.fail_json(msg='Failed to re-generate the poller Local')
    body = r.status_code

    module.exit_json(changed=True,result=body)

# import module snippets (must stay here after your code)
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()



