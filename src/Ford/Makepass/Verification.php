<?php
namespace Recallg\Makepass;

use Recallg\MakepassMd5\Md5;
/**
 *
 */
class Verification
{
	/**
	 * [getMd5 获取加密md5值]
	 * @param  string $str [description]
	 * @return [type]      [description]
	 */
	private function getMd5($str = '')
	{
		$obj = New MD5($str);
		return $obj->getDigist();
	}

	/**
	 * [encryption 生成密码]
	 * @author jiazhizhong
	 * @param  string $password [明文密码]
	 * @return [type]           [description]
	 */
	public function encryption($password = '')
	{
	    $j = 0;
	    $encryption = '';
	    $time = time();
	    $key2 = sha1($password);
	    $pass_key = $this->getMd5($password);
	    $pass_key = password_hash($pass_key, PASSWORD_DEFAULT);
	    $time_arr = str_split($time);
	    rsort($time_arr);
	    $time_str = base64_encode(str_replace(',', '', implode(',', $time_arr)));
	    $key2_arr = str_split($key2);
	    $time_arr = str_split($time_str);
	    $time_len = count($time_arr);
	    foreach ($key2_arr as $key => $value) {
	        if ($key%2 == 0 && $j <= $time_len-3) {
	            $encryption .= $time_arr[$j] . $value;
	            $j++;
	        }else{
	            $encryption .= $value;
	        }
	    }
	    return $pass_key."$:".$encryption."==";
	}

	/**
	 * [decryption 验证密码]
	 * @author jiazhizhong
	 * @param  string $encryption [加密串]
	 * @param  string $password   [明文密码]
	 * @return [type]             [description]
	 */
	public function decryption($password = '', $encryption = ''){
		if (!empty($encryption)) {
			$j = 0;
			$key2_str = '';
			$time_key_str = '';
			$info = explode('$:', $encryption);
			$info[1] = str_replace('=', '', $info[1]);
			$key_arr = str_split($info[1]);
			foreach ($key_arr as $key => $value) {
				if ($key%3 == 0 && $j <= 13) {
					$time_key_str .= $key_arr[$key];
					$j++;
				}else{
					$key2_str .= $value;
				}
			}
			$time_key_str = $time_key_str."==";
			$time = base64_decode($time_key_str);
			if (is_numeric($time)) {
				$key2 = sha1($password);
				if ($key2 == $key2_str)
				{
					$password = $this->getMd5($password);
					return password_verify($password, $info[0]);
				}
			}
			return false;
		}
		return false;
	}
}
