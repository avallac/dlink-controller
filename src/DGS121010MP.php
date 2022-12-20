<?php

namespace Avallac\DlinkController;

class DGS121010MP extends AbstractController
{
    protected $ip;
    protected $code;
    protected $password;
    protected $config;

    const VERSION = '6.20.B013';
    const PROTO = 'HTTPS://';

    const PROBLEM_NO = 0;
    const PROBLEM_OLD_VERSION = 1;
    const PROBLEM_ACTIVE_OLD_VERSION = 2;

    const FW_STATUS_OK = 0;
    const FW_STATUS_UPDATING = 1;
    const FW_STATUS_UPDATED = 3;

    public function __construct($ip, $config, $password = 'admin', $url = '/homepage.htm')
    {
        $this->config = $config;
        $this->startTest('Авторизация');
        $this->ip = $ip;
        $this->password = $password;
        $uri = self::PROTO . $ip . '/Encrypt.js';
        $data = (string)(new \GuzzleHttp\Client())->request('GET', $uri, ['verify' => false])->getBody();
        if (!preg_match('|EN_DATA = \'([^\']+)\'|', $data, $m)) {
            throw new \Exception($data);
        }

        $pub = "-----BEGIN PUBLIC KEY-----\n" . $m[1] . "\n-----END PUBLIC KEY-----";
        $pk  = openssl_get_publickey($pub);
        openssl_public_encrypt('admin', $encrypted1, $pk);
        openssl_public_encrypt($password, $encrypted2, $pk);

        $param = [
            'form_params' => [
                'pelican_ecryp' => base64_encode($encrypted1),
                'pinkpanther_ecryp' => base64_encode($encrypted2),
                'BrowsingPage' => 'index_redirect.htm',
                'currlang' => 0,
                'changlang' => 0
            ],
            'verify' => false
        ];

        $uri = self::PROTO . $ip . $url;
        $resp = (new \GuzzleHttp\Client())->request('POST', $uri, $param);
        if (!preg_match('|Gambit=([A-F\d]+)"|', (string)($resp->getBody()), $m)) {
            $this->resultTest(false);
            $this->addError('Не удалось авторизоваться', []);
            return;
        }
        $this->code = $m[1];
        $this->resultTest(true);
    }

    public function updatePassword($newPassword)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'pass_set',
                'old_pass' => $this->password,
                'new_pass' => $newPassword,
                'renew_pass' => $newPassword,
                'over' => ''
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Password.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function request($uri)
    {
        return (new \GuzzleHttp\Client())->request('GET', $uri, ['verify' => false]);
    }

    protected function checkVersion()
    {
        $result = true;
        $this->startTest('Проверка версии');
        $uri = self::PROTO . $this->ip . '/iss/specific/Device.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data,  "var Switch_Status = ['DGS-1210-10MP', '6.20.B013'") === false) {
            $this->addError('Не совпадает версия коммутатора или версия прошивки', $data);
            $result = false;
        }

        $this->resultTest($result);
    }

    protected function findAcl($name)
    {
        $data = $this->getACL();
        $found = null;
        foreach ($data as $id => $datum) {
            if ($datum[1] === $name) {
                $found = $datum;
            }
        }

        return $found;
    }

    protected function addACL($name)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'aclAccProAdd',
                'AccName' => $name,
                'FrameType' => '13',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLProfile_cisco_like.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function deleteRule($ruleId)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'aclrulebrowser_rule',
                'postComplexID' => 65536 + (int)$ruleId,
                'postActionType' => 'delete',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLRule.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function addRule($ruleId)
    {
        $acl = $this->config['ACL'] ?? [];
        $ip = $acl[$ruleId - 100] ?? null;
        if ($ruleId === 200) {
            $rule = [
                'postAccessID' => '200',
                'SrcIP_Sel' => '2',
                'DstIP_Sel' => '2',
                'ProtocolTypeChk' => 'on',
                'ProtoType_Sel' => '6',
                'TCPsrcPort' => '',
                'TCPsrcPortMask' => '',
                'TCPdesPort' => '',
                'TCPdesPortMask' => '',
                'action' => '2',
            ];
        } elseif (!empty($ip)) {
            $rule = [
                'postAccessID' => (string)$ruleId,
                'SrcIP_Sel' => '2',
                'DstIP_Sel' => '1',
                'DstIPstr' => $ip,
                'dstIP_Mask' => '255.255.255.255',
                'action' => '1',
            ];
        } else {
            throw new \Exception('ошибка с ACL правилом' . $ruleId);
        }

        $data['form_params'] = $rule;
        $data['form_params']['Gambit'] = $this->code;
        $data['form_params']['FormName'] = 'aclruleAdd_rule';
        $data['form_params']['postProfileID'] = '1';
        $data['form_params']['postActionType'] = 'create';
        $data['form_params']['tempAccessID'] = '';
        $data['form_params']['Sequence_No_Sel'] = '1';
        $data['verify'] = false;

        $uri = self::PROTO . $this->ip . '/iss/specific/ACLRule.js?profileID=1';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkACLNumRules($tryToUpdate)
    {
        $template = [
            '200' => ['1','13','6','200','2','1']
        ];
        $acl = $this->config['ACL'] ?? [];

        $id = 100;
        foreach ($acl as $ip) {
            $template[(string)$id] = ['1','13','256',(string)$id,'1','1'];
            $id++;
        }

        $result = true;
        $this->startTest('Проверка списка правил ACL');

        $data = $this->getACLRules();
        foreach ($data as $datum) {
            $id = $datum['3'];
            if (!isset($template[$id]))  {
                $this->addError('Лишнее правило id:' . $id, []);
                $result = false;
                if ($tryToUpdate) {
                    $this->deleteRule($id);
                }
            } elseif ($template[$id] !== $datum) {
                $this->addError('Проблема с правилом id:' . $id, []);
                $result = false;
                if ($tryToUpdate) {
                    $this->deleteRule($id);
                }
            } else {
                unset($template[$id]);
            }
        }

        foreach ($template as $id => $item) {
            $this->addError('Не найдено правило id:' . $id, []);
            $result = false;
            $this->addRule($id);
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->checkACLNumRules(false);
        }
    }

    protected function checkACL($tryToUpdate)
    {
        $acl = 'DOMOFON';
        $result = true;
        $this->startTest('Проверка ACL');
        $data = $this->findAcl($acl);
        if ($data === null) {
            $this->addError('Не обнаружен ACL', []);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->addACL($acl);
            $this->checkACL(false);
        }
    }

    protected function checkRules($tryToUpdate)
    {
        $result = true;
        $acl = $this->config['ACL'] ?? [];
        if (empty($acl)) {
            $this->addError('ACL не задан в файле конфигурации', []);
            $this->resultTest(false);
            return;
        }

        $this->startTest('Проверка правил ACL');
        $numRule = 100;
        foreach ($acl as $ip) {
            $data = $this->getACLRule($numRule);
            if ($data !== '[["1","PROFILEID","01"],["1","SourceIP","0.0.0.0"],["1","DestinationIP","' . $ip . '"],["1","SourceIPMask","0.0.0.0"],["1","DestinationIPMask","255.255.255.255"],["1","IPProtocol","256"],["1","SourcePort","-1"],["1","DestinationPort","-1"],["1","SourcePortMask","ffff"],["1","DestinationPortMask","ffff"],["1","ICMPType","-1"],["1","ICMPCode","-1"],["1","IGMPType","-1"],["1","TOS","-1"],["1","DSCP","-1"],["1","Access",["1",""]],["1","Priority",-1],["1","ReplacePriority",2]]') {
                $this->addError('Ошибка в правиле ' . $numRule, $data);
                $result = false;
                if ($tryToUpdate) {
                    $this->deleteRule($numRule);
                    $this->addRule($numRule);
                }
            }
            $numRule ++;
        }

        $data = $this->getACLRule(200);
        if ($data !== '[["1","PROFILEID","01"],["1","SourceIP","0.0.0.0"],["1","DestinationIP","0.0.0.0"],["1","SourceIPMask","0.0.0.0"],["1","DestinationIPMask","0.0.0.0"],["1","IPProtocol","6"],["1","SourcePort","-1"],["1","DestinationPort","-1"],["1","SourcePortMask","ffff"],["1","DestinationPortMask","ffff"],["1","ICMPType","-1"],["1","ICMPCode","-1"],["1","IGMPType","-1"],["1","TOS","-1"],["1","DSCP","-1"],["1","Access",["2",""]],["1","Priority",-1],["1","ReplacePriority",2]]') {
            $this->addError('Ошибка в правиле ' . 200, $data);
            $result = false;
            if ($tryToUpdate) {
                $this->deleteRule(200);
                $this->addRule(200);
            }
        }
        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->checkRules(false);
        }
    }

    protected function checkBindAcl($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка ACL на портах');
        $aclPorts = [];
        $vlans = $this->getVlan();
        foreach ($vlans as $vlan) {
            $vis = (int)$vlan[0];
            if ($vis >= 300 && $vis <= 399) {
                $ports = str_split($vlan[2]);
                foreach ($ports as $id => $port) {
                    if ($port === 'U') {
                        $aclPorts[$id + 1] = 1;
                    }
                }
            }
        }
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLBindPort.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();

        preg_match_all('~^var\s+([^=]+?)\s*=\s*(.+?)\s*;\s*$~imus', $data, $matchesAll, PREG_SET_ORDER);
        $arr = [];
        foreach ($matchesAll as $matches) {
            $arr[$matches[1]] = $matches[2];
        }
        $string = str_replace(["\r\n", "\n", " ", "\t"], '', $arr['AclBindPortTable']);
        $string = str_replace("'", '"', $string);
        $data = json_decode($string, true);
        foreach ($data as $datum) {
            $id = (int)$datum['0'];
            if ($datum[1] !== '0') {
                if ($tryToUpdate) {
                    $this->clearAclToPort($id);
                }
                $result = false;
                $this->addError('MAC ACL на порту ' . $id, []);
            }
            if ($datum[5] !== '0') {
                if ($tryToUpdate) {
                    $this->clearAclToPort($id);
                }
                $result = false;
                $this->addError('IPv6 ACL на порту ' . $id, []);
            }
            if (!empty($aclPorts[$id])) {
                if ($datum[3] !== '1') {
                    if ($tryToUpdate) {
                        $this->bindAclToPort(1, $id);
                    }
                    $result = false;
                    $this->addError('Нет ACL на порту ' . $id, []);
                } elseif ($datum[4] !== 'DOMOFON') {
                    if ($tryToUpdate) {
                        $this->bindAclToPort(1, $id);
                    }
                    $result = false;
                    $this->addError('Неправильный ACL на порту ' . $id, []);
                }
            } else {
                if ($datum[3] !== '0') {
                    if ($tryToUpdate) {
                        $this->clearAclToPort($id);
                    }
                    $result = false;
                    $this->addError('IPv4 ACL на порту ' . $id, []);
                }
            }
        }
        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->checkBindAcl(false);
        }
    }

    protected function bindAclToPort($num, $port)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'aclbindPort',
                'SetPort' => $port,
                'IPv4AccessListChk' => 'on',
                'IPv4AccessList_Sel' => $num,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLBindPort.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function clearAclToPort($port)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'aclbindPort',
                'SetPort' => $port,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLBindPort.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkPortSpeed($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка cкорости порта');
        $vlanPort = [];
        $vlans = $this->getVlan();
        foreach ($vlans as $vlan) {
            $vis = (int)$vlan[0];
            if ($vis >= 300 && $vis <= 499) {
                $ports = str_split($vlan[2]);
                foreach ($ports as $id => $port) {
                    if ($port === 'U') {
                        $vlanPort[$id + 1] = 1;
                    }
                }
            }
        }
        $uri = self::PROTO . $this->ip . '/iss/specific/PortSetting.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();

        $data = str_replace('var PORT_CAPABILITY_ADVERTISE_STATE', "\nvar PORT_CAPABILITY_ADVERTISE_STATE", $data);
        preg_match_all('~^var\s+([^=]+?)\s*=\s*(.+?)\s*;\s*$~imus', $data, $matchesAll, PREG_SET_ORDER);
        $arr = [];
        foreach ($matchesAll as $matches) {
            $arr[$matches[1]] = $matches[2];
        }
        $string = str_replace(["\r\n", "\n", " ", "\t"], '', $arr['PORT_CAPABILITY_ADVERTISE_STATE']);
        $string = str_replace("'", '"', $string);
        $data = json_decode($string, true);

        foreach ($data as $datum) {
            $id = (int)$datum['0'];
            if (!empty($vlanPort[$id])) {
                if (strpos($datum[1], '1000_full') !== false) {
                    if ($tryToUpdate) {
                        $this->updatePortSpeed($id);
                    }
                    $result = false;
                    $this->addError('Неправильная скорость порта ' . $id, []);
                }
            }
        }
        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->checkPortSpeed(false);
        }
    }

    protected function updatePortSpeed($port)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'portset',
                'port_f' => $port - 1,
                'port_t' => $port - 1,
                'speed' => 5,
                'mdi' => 0,
                'flow' => 0,
                'autodingrade' => 2,
                'post_url' => 'cgi_port',
                'chk10_half' => 'on',
                'chk10_full' => 'on',
                'chk100_half' => 'on',
                'chk100_full' => 'on',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/PortSetting.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkSystem($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка System Name/System Location');
        $uri = self::PROTO . $this->ip . '/iss/specific/Sys.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data,  "var Smart_Wizard_show = 0;") === false) {
            $this->addError('Не выключен Smart Wizard', $data);
            $result = false;
        }
        if (preg_match("|SysInfo_Setting = \[\d+,\d+,\'SW_(\d)(\d)(\d)_(\d+)\',\'38K(\d)_P(\d+)_F(\d+)\', \d\]|", $data, $m)) {
            if ($m[1] !== $m[5]) {
                $this->addError('В System Name и System Location не совпадает дом', $data);
                $result = false;
            }
            if ($m[3] !== $m[6]) {
                $this->addError('В System Name и System Location не совпадает подъезд', $data);
                $result = false;
            }
            if ($m[4] !== $m[7]) {
                $this->addError('В System Name и System Location не совпадает этаж', $data);
                $result = false;
            }
        } else {
            $this->addError('Не удалось разобрать System Name/System Location', $data);
            $result = false;
        }

        $this->resultTest($result);
        if (!$result && $tryToUpdate) {
            $this->updateSystemName();
            $this->checkSystem(false);
        }
    }

    protected function updateSystemName()
    {
        if (preg_match('|10\.10\.(\d)0(\d)\.(\d+)|', $this->ip, $m)) {
            $building = $m[1];
            $p = $m[2];
            $e = $m[3];
            $sys = 'SW_' . $building . '0' . $p . '_' . $e;
            $loc = '38K' . $building . '_P' . $p . '_F' . $e;
            $this->updateName($sys, $loc);
        }
    }

    protected function checkSNMP($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка SNMP');

        $uri = self::PROTO . $this->ip . '/iss/specific/SNMP_GlobalState.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data,  "var SNMP_GlobalState = '1';") === false) {
            $this->addError('SNMP выключен', $data);
            $result = false;
        }
        $uri = self::PROTO . $this->ip . '/iss/specific/SNMP.js?Gambit=' . $this->code;
        $community = $this->config['SNMP'] ?? null;
        $data = (string)($this->request($uri))->getBody();
        $foundValidSNMP = false;

        if (!$community) {
            $this->addError('SNMP не задан в конфиге', $data);
            $result = false;
        } elseif (strpos($data, "var SNMP_Data = [];") !== false) {
            $this->addError('Нет SNMP community', []);
            $result = false;
            if ($tryToUpdate) {
                $this->addSNMP($community, 'ReadWrite');
            }
        } elseif (preg_match("|var SNMP_Data = (\[[^;]+\]);|s", $data, $m)) {
            $string = str_replace(["\r\n", "\n", " ", "\t"], '', $m[1]);
            $string = str_replace("'", '"', $string);
            $snmpConfig = json_decode($string, true);
            if (!empty($snmpConfig)) {
                foreach ($snmpConfig as $item) {
                    if ($item[1] !== $community || $item[0] !== 'ReadWrite') {
                        $this->addError('Неправильный SNMP' . $item[0] . ':' . $item[1], []);
                        $result = false;
                        if ($tryToUpdate) {
                            $this->rmSNMP($item[1], $item[0]);
                        }
                    } else {
                        $foundValidSNMP = true;
                    }
                }

                if (!$foundValidSNMP) {
                    $result = false;
                    $this->addError('Не найден правильный SNMP', []);
                    if ($tryToUpdate) {
                        $this->addSNMP($community, 'ReadWrite');
                    }
                }
            } else {
                $result = false;
                $this->addError('Не удалось получить конфигурацию SNMP', $data);
            }
        } else {
            $result = false;
            $this->addError('Не удалось получить конфигурацию SNMP', $data);
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate && $community) {
            $this->checkSNMP(false);
        }
    }

    protected function rmSNMP($community, $view)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'COMMUNITY_INDEX' => $community,
                'SECURITY_NAME' => $view,
                'ACTION' => 'Delete',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/SNMP_Community.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function addSNMP($community, $view)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'COMMUNITY_INDEX' => $community,
                'SECURITY_NAME' => $view,
                'applybutton' => 'Add',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/SNMP_Community.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkSNTP(bool $tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка sNTP');
        $uri = self::PROTO . $this->ip . '/iss/specific/SNTPTimeSet.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        $ntpServer = $this->config['NTP'] ?? null;
        if (!empty($ntpServer)) {
            if (strpos($data, "SNTP_Server = ['" . $ntpServer . "','0.0.0.0','30'];") === false &&
                strpos($data, "SNTP_Server = ['" . $ntpServer . "','0.0.0.0','0.0.0.0','30'];") === false) {
                $this->addError('sNTP не настроен', $data);
                $result = false;
            }

            if (strpos($data, "var SNTP_Time_Status = [1,") === false) {
                $this->addError('sNTP не включен', $data);
                $result = false;
            }
        } else {
            $this->addError('sNTP не задан в конфигурации', $data);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate && !empty($ntpServer)) {
            $this->updateSNTP($ntpServer);
            $this->checkSNTP(false);
        }
    }

    protected function updateSNTP($ntpServer)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'PriSrvIpType' => 1,
                'SecSrvIpType' => 1,
                'Pri_IsLinkLocal' => 0,
                'Sec_IsLinkLocal' => 0,
                'PriInterfaceName' => '',
                'SecInterfaceName' => '',
                'h_day' => '',
                'h_mon' => '',
                'h_year' => '',
                'hr' => '',
                'min' => '',
                'sec' => '',
                'SNTP_STATUS' => 1,
                'pri_radio_serverip' => 1,
                'PRI_SERVER_v4' => $ntpServer,
                'sec_radio_serverip' => 1,
                'SEC_SERVER_v4' => '0.0.0.0',
                'POLL_TIME' => 30,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/SNTPTimeSet.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkLLDP($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка LLDP');
        $uri = self::PROTO . $this->ip . '/iss/specific/LLDP.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data, "var LLDP_Enable = '1';") === false) {
            $this->addError('Не включен LLDP', $data);
            $result = false;
        }
        if (strpos($data, "var LLDP_Forward_Enable = '2';") === false) {
            $this->addError('Включена пересылка LLDP', $data);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->updateLLDP();
            $this->checkSysLogEnable(false);
        }
    }

    protected function updateLLDP()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'formLLDPSetting',
                'enabled_flag' => 1,
                'Forward_enabled_flag' => 2,
                'LLDPHoldTime' => 4,
                'LLDPTimer' => 30,
                'LLDPReinitDelay' => 2,
                'LLDPTxDelay' => 2
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/LLDP.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkSysLogEnable($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка SysLog');
        $uri = self::PROTO . $this->ip . '/iss/specific/R25_SystemLogSetting.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data, "var SyslogOnOff = [ '1'];") === false) {
            $this->addError('Syslog не включен', $data);
            $result = false;
        }
        if (strpos($data, "var SyslogSavemode = ['0','30'];") === false) {
            $this->addError('Syslog не настроен', $data);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->updateSysLog();
            $this->checkSysLogEnable(false);
        }
    }

    protected function updateSysLog()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'inputstyle' => 0,
                'glbEn' => 1,
                'S1' => 0,
                'remove event' => ''
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/R25_SystemLogSetting.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);

        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'formsystemlog',
                'SrvIpType' => 1,
                'IsLinkLocal' => 0,
                'InterfaceName' => '',
                'DestinationIP' => '',
                'radio_serverip' => 'on',
                'DesIP' => '10.2.2.101',
                'Tlog' => 7,
                'FA' => 184,
                'UP' => 514,
                'Time_Stamp' => 1
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/SystemLogSetting.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkSysLogSettings($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка сервера SysLog');
        $uri = self::PROTO . $this->ip . '/iss/specific/SystemLogSetting.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data, "var System_Log_Setting = ['1', '10.2.2.101', '7', '514' , '184', '1'];") === false) {
            $this->addError('Syslog сервер не настроен', $data);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->updateSysLog();
            $this->checkSysLogSettings(false);
        }
    }

    protected function checkSafeguardEngine($tryToUpdate)
    {
        $result = true;
        $this->startTest('Проверка SafeguardEngine');
        $uri = self::PROTO . $this->ip . '/iss/specific/Safeguard.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data, "SafeguardEngine_Enable = '0';") === false) {
            $this->addError('SafeguardEngine не выключен', $data);
            $result = false;
        }

        $this->resultTest($result);

        if (!$result && $tryToUpdate) {
            $this->updateSafeguardEngine();
            $this->checkSafeguardEngine(false);
        }
    }

    protected function updateSafeguardEngine()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'sgtype' => 0
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Safeguard.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    protected function checkPortError()
    {
        $result = true;
        $this->startTest('Проверка ошибок на портах');
        $uri = self::PROTO . $this->ip . '/iss/specific/Statistics_js.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (preg_match("|var Statistics = (\[[^;]+\]);|s", $data, $m)) {
            $string = str_replace( ["\r\n", "\n", " ", "\t", "'"], '', $m[1]);
            $stat = json_decode($string, true);
            foreach ($stat as $port) {
                if ($port[3] || $port[4]) {
                    $this->addError('Порт ' . $port[0] . ' содержит ошибки', $data);
                    $result = false;
                }
            }
        } else {
            $this->addError('Не удалось собрать статистику', $data);
            $result = false;
        }

        $this->resultTest($result);
    }

    protected function getPortDescription()
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/PortDescSetting.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (preg_match("|var Port_Description = (\[[^;]+\]);|s", $data, $m)) {
            $string = str_replace(["\r\n", "\n", " ", "\t"], '', $m[1]);
            $string = str_replace("'", '"', $string);
            return json_decode($string, true);
        }

        return [];
    }

    public function getPortState()
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/PortSetting.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (preg_match("|var Port_Setting = (\[[^;]+\]);|s", $data, $m)) {
            $string = str_replace(["\r\n", "\n", " ", "\t"], '', $m[1]);
            $string = str_replace("'", '"', $string);
            return json_decode($string, true);
        }

        return [];
    }

    public function getACL()
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLProfile_cisco_like.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        preg_match_all('~^var\s+([^=]+?)\s*=\s*(.+?)\s*;\s*$~imus', $data, $matchesAll, PREG_SET_ORDER);
        $arr = array();
        foreach ($matchesAll as $matches) {
            $arr[$matches[1]] = $matches[2];
        }
        $string = $arr['ACLProfileDetail_List'];
        $string = str_replace(["\r\n", "\n", " ", "\t"], '', $string);
        $string = str_replace("'", '"', $string);
        return json_decode($string, true);
    }

    public function getACLRules()
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLFindAclrule.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        preg_match_all('~^var\s+([^=]+?)\s*=\s*(.+?)\s*;\s*$~imus', $data, $matchesAll, PREG_SET_ORDER);
        $arr = [];
        foreach ($matchesAll as $matches) {
            $arr[$matches[1]] = $matches[2];
        }

        $string = $arr['FindAclrule'];
        $string = str_replace(["\r\n", "\n", " ", "\t"], '', $string);
        $string = str_replace("'", '"', $string);

        return json_decode($string, true);
    }

    public function getACLRule($ruleId)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'aclrulebrowser_rule',
                'postComplexID' => 65536 + $ruleId,
                'postActionType' => 'setRequestor',
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/ACLRule.js?profileID=1';
        $data = (new \GuzzleHttp\Client())->request('POST', $uri, $data);
        if (!preg_match('|<INPUT type="Hidden" name="Gambit" value="([\dA-Z]+)">|', $data->getBody(), $m)) {
            throw new \Exception('Проблема с кодом');
        }
        $code = $m[1];

        $url = self::PROTO . $this->ip . '/iss/specific/ACLRule.js?Gambit=' . $code;
        $output = (string)($this->request($url))->getBody();
        preg_match_all('~^var\s+([^=]+?)\s*=\s*(.+?)\s*;\s*$~imus', $output, $matchesAll, PREG_SET_ORDER);
        $arr = array();
        foreach ($matchesAll as $matches) {
            $arr[$matches[1]] = $matches[2];
        }

        $data = $arr['ACLruleList'];
        $data = str_replace(["\r\n", "\n", " ", "\t"], '',$data);
        $data = str_replace("'", '"', $data);

        return $data;
    }

    public function updatePortName($port, $description)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'port_f' => $port,
                'port_t' => $port,
                'port_description' => $description,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/PortDescSetting.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function supported() : bool
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/Device.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (strpos($data,  "DGS-1210-10MP") === false) {
            return false;
        }

        return true;
    }

    public function isActualVersion() : int
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/Multi_Image.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        foreach (['', '2'] as $num) {
            if (!preg_match('|var Multi_Image' . $num . ' = \[\'(\*?c?)\d\',\'([^\']+)\',|', $data, $m)) {
                throw new \Exception($data);
            }
            if ($m[2] === self::VERSION) {
                if ($m[1] !== '*' && $m[1] !== '*c') {
                    return self::PROBLEM_ACTIVE_OLD_VERSION;
                }

                return self::PROBLEM_NO;
            }
        }
        return self::PROBLEM_OLD_VERSION;
    }

    public function disableGuard()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'sgtype' => 0
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Safeguard.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function uploadImage()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'tftp_set',
                'tftp_type' => 2,
                'server_iptype' => 1,
                'IsLinkLocal' => 0,
                'InterfaceName'=> '',
                'bb' => 0,
                'serverip' => '10.2.2.203',
                'radio_serverip' => 'on',
                'filename' => 'DGS-1210-FX-SERIES-FX-6-20-B013.hex',
                'TftpImageID' => 2,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/TFTP_Firmware.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function setSecondFirmware()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'BootUPImageID' => 2
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Multi_Image.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function getUpdateStatus() : int
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/TFTP_Firmware.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (!preg_match('|var fw_status=(\d);|', $data, $m)) {
            throw new \Exception($data);
        }
        if ($m[1] === '1') {
            return self::FW_STATUS_UPDATING;
        } elseif ($m[1] === '0') {
            return self::FW_STATUS_OK;
        } elseif ($m[1] === '3') {
            return self::FW_STATUS_UPDATED;
        }

        throw new \Exception($m[1]);
    }

    public function reboot()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'reboot',
                'radsave_flag' => 1,
                'saveornot' => 1,
                'over' => ''
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Reboot_js.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function addVlan($newVlan, $vlanName, $ports)
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/QVLAN.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (!preg_match('|Tnum = (\d+);|s', $data, $m)) {
            throw new \Exception($data);
        }
        $tagId = (int)$m[1];
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'formAddVLAN',
                'tag_id' => $tagId,
                'VID' => $newVlan,
                'VlanName' => $vlanName,
                'over' => ''
            ],
            'verify' => false
        ];
        foreach (str_split($ports) as $id => $type) {
            $data['form_params']['C' . ($id +1)] = $type;
        }
        $uri = self::PROTO . $this->ip . '/iss/specific/QVLAN.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function rmVlan($vlan)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'formVLAN',
                'VLAN_action' => 'Delete',
                'VID' => $vlan,
                'vname' => '',
                'over' => ''
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/QVLAN.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function vlanExists($newVlan) : bool
    {
        $vlanInfo = $this->getVlan();
        foreach ($vlanInfo as $vlan) {
            if ($vlan[0] === $newVlan) {
                return true;
            }
        }

        return false;
    }

    public function isOldIp($ip)
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/IPv4_Interface.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (!preg_match('|Interface_Info = ([^;]+);|s', $data, $m)) {
            throw new \Exception($data);
        }
        $string = str_replace( ["\r\n", "\n", " ", "\t"], '', $m[1]);
        $info = json_decode(str_replace("'", '"', $string), true);
        if ($info[0][8] !== '150') {
            throw new \Exception($data);
        }

        if ($info[0][3] !== $ip) {
            throw new \Exception($data);
        }

        return true;
    }

    public function getVlan()
    {
        $uri = self::PROTO . $this->ip . '/iss/specific/QVLAN.js?Gambit=' . $this->code;
        $data = (string)($this->request($uri))->getBody();
        if (!preg_match('|TVLAN_Setting = ([^;]+);|s', $data, $m)) {
            throw new \Exception($data);
        }
        $string = str_replace( ["\r\n", "\n", " ", "\t"], '', $m[1]);
        return json_decode(str_replace("'", '"', $string), true);
    }

    public function checkVlan()
    {
        $result = true;
        $this->startTest('Проверка VLAN');
        $vlanConfig = [
            '1' => ['default', '0000000000'],
            '152' => ['Sds', null],
            '211' => ['FLOOR_SW_K1_P1', '000000000T'],
            '212' => ['FLOOR_SW_K1_P2', '000000000T'],
            '213' => ['FLOOR_SW_K1_P3', '000000000T'],
            '214' => ['FLOOR_SW_K1_P4', '000000000T'],
            '215' => ['FLOOR_SW_K1_P5', '000000000T'],
            '216' => ['FLOOR_SW_K1_P6', '000000000T'],
            '217' => ['FLOOR_SW_K1_P7', '000000000T'],
            '218' => ['FLOOR_SW_K1_P8', '000000000T'],
            '221' => ['FLOOR_SW_K2_P1', '000000000T'],
            '222' => ['FLOOR_SW_K2_P2', '000000000T'],
            '223' => ['FLOOR_SW_K2_P3', '000000000T'],
            '224' => ['FLOOR_SW_K2_P4', '000000000T'],
            '225' => ['FLOOR_SW_K2_P5', '000000000T'],
            '226' => ['FLOOR_SW_K2_P6', '000000000T'],
            '227' => ['FLOOR_SW_K2_P7', '000000000T'],
            '228' => ['FLOOR_SW_K2_P8', '000000000T'],
            '311' => ['DOMOFON_K1_P1', null],
            '312' => ['DOMOFON_K1_P2', null],
            '313' => ['DOMOFON_K1_P34', null],
            '315' => ['DOMOFON_K1_P56', null],
            '317' => ['DOMOFON_K1_P78', null],
            '321' => ['DOMOFON_K2_P12', null],
            '323' => ['DOMOFON_K2_P34', null],
            '325' => ['DOMOFON_K2_P56', null],
            '327' => ['DOMOFON_K2_P7', null],
            '328' => ['DOMOFON_K2_P8', null],
            '413' => ['FLOOR_CAM_K1_P3', null],
            '414' => ['FLOOR_CAM_K1_P4', null],
        ];
        $vlanInfo = $this->getVlan();
        foreach ($vlanInfo as $item) {
            $vid = $item[0];
            if (empty($vlanConfig[$vid])) {
                $this->addError('Vlan ' . $vid . ' неизвестен', $item);
                $result = false;
            } else {
                if ($vlanConfig[$vid][0] !== $item[1]) {
                    $this->addError('Vlan ' . $vid . ' неправльно назван', $item);
                    $result = false;
                }
                if (!empty($vlanConfig[$vid][1])) {
                    if ($vlanConfig[$vid][1] !== $item[2]) {
                        $this->addError('Vlan ' . $vid . ' неправльно сконфигурен', $item);
                        $result = false;
                    }
                }
            }
        }
        $this->resultTest($result);
    }

    public function updateIp($newIp, $oldIp, $gw, $vlan)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'sys_ip_set',
                'ipaddress' => $newIp,
                'gateway' => $gw,
                'submask' => '255.255.255.0',
                'dhcp' => 0,
                'preipaddress' => $oldIp,
                'pregateway' => '0.0.0.0',
                'presubmask' => '255.255.0.0',
                'predhcp' => 0,
                'interface_admin_state' => 1,
                'interface_name' => 'System',
                'changevlan' => 1,
                'vlan_name' => $vlan,
                'over' => '',
                'OptionEnable' => 2,
                'hostname' => 'DGS-1210-10MP',
                'dhcpretrytimes' => 7
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/Sys.js';
        try {
            (new \GuzzleHttp\Client())->request('POST', $uri, $data);
        } catch (\Throwable $e) {

        }
    }

    public function saveConfig()
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'SaveConfigID' => 1,
            ],
            'verify' => false
        ];
        $uri = self::PROTO . $this->ip . '/iss/specific/SaveConfig.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function updateName($sys, $loc)
    {
        $data = [
            'form_params' => [
                'Gambit' => $this->code,
                'FormName' => 'sys_set',
                'sys' => $sys,
                'loc' => $loc,
                'SysTimeout' => 5,
                'srv' => 80,
                'over' => ''
            ],
            'verify' => false
        ];

        $uri = self::PROTO . $this->ip . '/iss/specific/Sys.js';
        (new \GuzzleHttp\Client())->request('POST', $uri, $data);
    }

    public function check($fix)
    {
        if ($this->code) {
            $this->checkVersion();
            $this->checkSystem($fix);
            $this->checkSNMP($fix);
            $this->checkLLDP($fix);
            $this->checkSNTP($fix);
            $this->checkSafeguardEngine($fix);
            $this->checkPortError();
            $this->checkVlan();
            $this->checkPortSpeed($fix);
            $this->checkACL($fix);
            $this->checkACLNumRules($fix);
            $this->checkRules($fix);
            $this->checkBindAcl($fix);

            if ($fix) {
                print "Сохранение конфигурации\n";
                $this->saveConfig();
            }
        }

        return $this->result;
    }
}