<?php

namespace pekoe\wechat;


use think\facade\Log;
use think\facade\Cache;

/**
 * 微信
 * Class WechatLogic
 */
class Wechat
{

    private $token;
    private $encodingaeskey;
    private $appid;
    private $appsecret;
    public $logcallback;
    public $component_verify_ticket;
    public $component_access_token;
    private $_receive;
    private $encrypt_type;
    private $postxml;


    const API_URL_PREFIX = 'https://api.weixin.qq.com/cgi-bin';

    //第三方平台
    const COMPONENT_AUTH_URL = '/component/api_component_token';
    const COMPONENT_PRE_AUTH_CODE = '/component/api_create_preauthcode?';
    const COMPONENT_OAUTH_URL = 'https://mp.weixin.qq.com/cgi-bin/componentloginpage?';
    const COMPONENT_API_QUERY_AUTH = '/component/api_query_auth?';
    const COMPONENT_API_AUTHORIZER_TOKEN = '/component/api_authorizer_token?';
    const COMPONENT_API_GET_AUTHORIZER_INFO = '/component/api_get_authorizer_info?';
    const COMPONENT_API_GET_AUTHORIZER_OPTION = '/component/api_get_authorizer_option?';
    const COMPONENT_API_SET_AUTHORIZER_OPTION = '/component/api_set_authorizer_option?';
    const COMPONENT_API_GET_AUTHORIZER_LIST = '/component/api_get_authorizer_list?';

    public function __construct($type)
    {
        $config = Config('wechat.' . $type);
        $this->token = isset($config['token']) ? $config['token'] : '';
        $this->encodingaeskey = isset($config['encodingaeskey']) ? $config['encodingaeskey'] : '';
        $this->appid = isset($config['appid']) ? $config['appid'] : '';
        $this->appsecret = isset($config['appsecret']) ? $config['appsecret'] : '';
    }


    /**
     * For weixin server validation
     * @param bool $return 是否返回
     */
    public function valid($return = false)
    {
        $encryptStr = "";
        if ($_SERVER['REQUEST_METHOD'] == "POST") {
            $postStr = file_get_contents("php://input");
            file_put_contents('wechat/' . date('Ymd') . '_postxml.txt', $postStr . PHP_EOL, FILE_APPEND);
            $array = (array)simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
            $this->encrypt_type = isset($_GET["encrypt_type"]) ? $_GET["encrypt_type"] : '';
            if ($this->encrypt_type == 'aes') { //aes加密
                //$this->log($postStr);
                $encryptStr = $array['Encrypt'];
                $pc = new Prpcrypt($this->encodingaeskey);
                $array = $pc->decrypt($encryptStr, $this->appid);
                if (!isset($array[0]) || ($array[0] != 0)) {
                    if (!$return) {
                        die('decrypt error!');
                    } else {
                        return false;
                    }
                }
                $this->postxml = $array[1];
                if (!$this->appid)
                    $this->appid = $array[2];//为了没有appid的订阅号。
            } else {
                $this->postxml = $postStr;
            }
        } elseif (isset($_GET["echostr"])) {
            $echoStr = $_GET["echostr"];
            if ($return) {
                if ($this->checkSignature())
                    return $echoStr;
                else
                    return false;
            } else {
                if ($this->checkSignature())
                    die($echoStr);
                else
                    die('no access');
            }
        }

        if (!$this->checkSignature($encryptStr)) {
            if ($return)
                return false;
            else
                die('no access');
        }

        return true;
    }


    /**
     * For weixin server validation
     */
    private function checkSignature($str = '')
    {
        $signature = isset($_GET["signature"]) ? $_GET["signature"] : '';
        $signature = isset($_GET["msg_signature"]) ? $_GET["msg_signature"] : $signature; //如果存在加密验证则用加密验证段
        $timestamp = isset($_GET["timestamp"]) ? $_GET["timestamp"] : '';
        $nonce = isset($_GET["nonce"]) ? $_GET["nonce"] : '';

        $token = $this->token;
        $tmpArr = array($token, $timestamp, $nonce, $str);
        sort($tmpArr, SORT_STRING);
        $tmpStr = implode($tmpArr);
        $tmpStr = sha1($tmpStr);

        if ($tmpStr == $signature) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 日志记录，可被重载。
     * @param mixed $log 输入日志
     * @return mixed
     */
    protected function log($log)
    {
        if ($this->debug && function_exists($this->logcallback)) {
            if (is_array($log)) $log = print_r($log, true);
            return call_user_func($this->logcallback, $log);
        }
    }

    /**
     * 获取微信服务器发来的信息
     */
    public function getRev()
    {
        if ($this->_receive) return $this;
        $postStr = !empty($this->postxml) ? $this->postxml : file_get_contents("php://input");
        //兼顾使用明文又不想调用valid()方法的情况
        //$this->log($postStr);
        if (!empty($postStr)) {
            $this->_receive = (array)simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
        }

        return $this;
    }

    /**
     * 获取接收消息的类型
     */
    public function getRevType()
    {
        if (isset($this->_receive['MsgType']))
            return $this->_receive['MsgType'];
        else
            return false;
    }

    /**
     * 获取微信服务器发来的信息
     */
    public function getRevData()
    {
        return $this->_receive;
    }

    /**
     * 保存第三方平台component_verify_ticket
     * @return bool
     */
    public function saveComponentVerifyTicket()
    {
        $appid = $this->appid;
        if ($this->_receive['AppId'] != $this->appid || $this->_receive['InfoType'] != 'component_verify_ticket') {
            return false;
        }

        $authname = 'wechat:component:verify_ticket:' . $appid;
        $this->component_verify_ticket = $this->_receive['ComponentVerifyTicket'];
        $this->setCache($authname, $this->component_verify_ticket, 3600);

        echo 'success';
        return true;
    }

    /**
     * 获取第三方平台component_verify_ticket
     * @return bool
     */
    public function getComponentVerifyTicket()
    {

        if ($this->component_verify_ticket) {
            return $this->component_verify_ticket;
        }

        $appid = $this->appid;
        $authname = 'wechat:component:verify_ticket:' . $appid;
        $get_cache = $this->getCache($authname);
        if (!$get_cache) {
            return false;
        }
        $this->component_verify_ticket = $get_cache;

        return $this->component_verify_ticket;
    }

    /**
     * 获取第三方平台component_access_token
     * @param string $appid 如在类初始化时已提供，则可为空
     * @param string $appsecret 如在类初始化时已提供，则可为空
     * @param string $component_access_token 手动指定component_access_token，非必要情况不建议用
     */
    public function checkComponentAuth($appid = '', $appsecret = '', $component_access_token = '')
    {
        if (!$appid || !$appsecret) {
            $appid = $this->appid;
            $appsecret = $this->appsecret;
        }
        if ($component_access_token) { //手动指定token，优先使用
            $this->component_access_token = $component_access_token;
            return $this->component_access_token;
        }

        $authname = 'wechat:component:access_token:' . $appid;
        if ($rs = $this->getCache($authname)) {
            $this->component_access_token = $rs;
            return $rs;
        }

        //获取component_verify_ticket
        if (!$this->getComponentVerifyTicket()) {
            return false;
        }

        $params = array(
            'component_appid' => $appid,
            'component_appsecret' => $appsecret,
            'component_verify_ticket' => $this->component_verify_ticket,
        );

        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_AUTH_URL, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }
            $this->component_access_token = $json['component_access_token'];
            $expire = $json['expires_in'] ? intval($json['expires_in']) - 100 : 3600;
            $this->setCache($authname, $this->component_access_token, $expire);
            return $this->component_access_token;
        }
        return false;
    }


    /**
     * 获取第三方平台预授权码
     * @return bool|mixed
     */
    public function getComponentPreAuthCode()
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;
        $params = array(
            'component_appid' => $this->appid,
        );
        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_PRE_AUTH_CODE . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 获取第三方平台OAuth uri
     * @param $redirect_uri
     * @param $auth_type string 要授权的帐号类型， 1则商户扫码后，手机端仅展示公众号、2表示仅展示小程序，3表示公众号和小程序都展示。
     *                          如果为未制定，则默认小程序和公众号都展示。第三方平台开发者可以使用本字段来控制授权的帐号类型。
     * @return bool|string
     */
    public function getComponentOAuthUri($redirect_uri, $auth_type = 3)
    {
        $code = $this->getComponentPreAuthCode();
        if (!$code) {
            return false;
        }
        $url = self::COMPONENT_OAUTH_URL . 'component_appid=' . $this->appid . '&pre_auth_code=' . $code['pre_auth_code'] .
            '&redirect_uri=' . urlencode($redirect_uri) . '&auth_type=' . $auth_type;
        return $url;
    }

    /**
     * 第三方平台查询公众号或小程序的接口调用凭据和授权信息
     * @param $redirect_uri
     * @return bool|string
     */
    public function queryComponentApiAuth($authorization_code)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'authorization_code' => $authorization_code
        );
        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_QUERY_AUTH . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 第三方平台查询公众号或小程序的接口调用凭据和授权信息
     * @param $redirect_uri
     * @return bool|string
     */
    public function refreshComponentAuthorizerToken($authorizer_appid, $authorizer_refresh_token)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'authorizer_appid' => $authorizer_appid,
            'authorizer_refresh_token' => $authorizer_refresh_token
        );
        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_AUTHORIZER_TOKEN . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 获取授权方的帐号基本信息
     * @param string $authorizer_appid 授权方appid
     * @return bool|string
     */
    public function getComponentAuthorizerInfo($authorizer_appid)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'authorizer_appid' => $authorizer_appid
        );
        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_GET_AUTHORIZER_INFO . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 第三方平台获取授权方的选项设置信息
     * @param string $authorizer_appid 授权方appid
     * @param string $option_name 选项名称 location_report,地理位置上报选项;voice_recognize,语音识别开关选项;customer_service,多客服开关选项;
     * @return bool|string
     */
    public function getComponentAuthorizerOption($authorizer_appid, $option_name)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'authorizer_appid' => $authorizer_appid,
            'option_name' => $option_name
        );

        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_GET_AUTHORIZER_OPTION . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 第三方平台获取授权方的选项设置信息
     * @param string $authorizer_appid 授权方appid
     * @param string $option_name 选项名称 location_report,地理位置上报选项;voice_recognize,语音识别开关选项;customer_service,多客服开关选项;
     * @param string $option_value 设置的选项值
     * @return bool|string
     */
    public function setComponentAuthorizerOption($authorizer_appid, $option_name, $option_value)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'authorizer_appid' => $authorizer_appid,
            'option_name' => $option_name,
            'option_value' => $option_value,
        );

        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_SET_AUTHORIZER_OPTION . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || !(isset($json['errcode']) && $json['errcode'] == 0)) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }

    /**
     * 第三方平台拉取当前所有已授权的帐号基本信息
     * @param string $authorizer_appid 授权方appid
     * @param string $option_name 选项名称 location_report,地理位置上报选项;voice_recognize,语音识别开关选项;customer_service,多客服开关选项;
     * @param string $option_value 设置的选项值
     * @return bool|string
     */
    public function getComponentAuthorizerList($offset = 0, $count = 100)
    {
        if (!$this->component_access_token && !$this->checkComponentAuth()) return false;

        $params = array(
            'component_appid' => $this->appid,
            'offset' => $offset,
            'count' => $count
        );

        $result = $this->http_post(self::API_URL_PREFIX . self::COMPONENT_API_GET_AUTHORIZER_LIST . 'component_access_token=' . $this->component_access_token, self::json_encode($params));
        if ($result) {
            $json = json_decode($result, true);
            if (!$json || isset($json['errcode'])) {
                $this->errCode = $json['errcode'];
                $this->errMsg = $json['errmsg'];
                return false;
            }

            return $json;
        }
        return false;
    }


    /**
     * GET 请求
     * @param string $url
     */
    public function http_get($url)
    {
        $oCurl = curl_init();
        if (stripos($url, "https://") !== FALSE) {
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, FALSE);
            curl_setopt($oCurl, CURLOPT_SSLVERSION, 1); //CURL_SSLVERSION_TLSv1
        }
        curl_setopt($oCurl, CURLOPT_URL, $url);
        curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1);
        $sContent = curl_exec($oCurl);
        $aStatus = curl_getinfo($oCurl);
        curl_close($oCurl);
        if (intval($aStatus["http_code"]) == 200) {
            return $sContent;
        } else {
            return false;
        }
    }

    /**
     * POST 请求
     * @param string $url
     * @param array $param
     * @param boolean $post_file 是否文件上传
     * @return string content
     */
    public function http_post($url, $param, $post_file = false)
    {
        $oCurl = curl_init();
        if (stripos($url, "https://") !== FALSE) {
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($oCurl, CURLOPT_SSLVERSION, 1); //CURL_SSLVERSION_TLSv1
        }
        if (is_string($param) || $post_file) {
            $strPOST = $param;
        } else {
            $aPOST = array();
            foreach ($param as $key => $val) {
                $aPOST[] = $key . "=" . urlencode($val);
            }
            $strPOST = join("&", $aPOST);
        }
        curl_setopt($oCurl, CURLOPT_URL, $url);
        curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($oCurl, CURLOPT_POST, true);
        curl_setopt($oCurl, CURLOPT_POSTFIELDS, $strPOST);
        $sContent = curl_exec($oCurl);
        $aStatus = curl_getinfo($oCurl);
        curl_close($oCurl);
        if (intval($aStatus["http_code"]) == 200) {
            return $sContent;
        } else {
            return false;
        }
    }

    /**
     * 设置缓存
     * @param string $cachename
     * @param mixed $value
     * @param int $expired
     * @return boolean
     */
    protected function setCache($cachename, $value, $expired)
    {
        //TODO: set cache implementation
        Cache::set($cachename, $value, $expired);
        return false;
    }

    /**
     * 获取缓存
     * @param string $cachename
     * @return mixed
     */
    protected function getCache($cachename)
    {
        //TODO: get cache implementation
        return Cache::get($cachename);
    }

    /**
     * 清除缓存
     * @param string $cachename
     * @return boolean
     */
    protected function removeCache($cachename)
    {
        //TODO: remove cache implementation
        return Cache::rm($cachename);
    }

    /**
     * 微信api不支持中文转义的json结构
     * @param array $arr
     */
    static function json_encode($arr)
    {
        //php5.4 json_encode才支持第二个参数：JSON_UNESCAPED_UNICODE ,中文不会被默认转成unicode
        //官方已修复
        return json_encode($arr, JSON_UNESCAPED_UNICODE);
    }

}
