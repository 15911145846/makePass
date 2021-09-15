<?php
namespace Recallg\Makepass;

// $str = "123456";
// $md5 = new MD5($str);
// echo $md5->getDigist();
// echo "<br />", md5($str);

class MD5 {
    const CHAR_ALIGNMENT = 8;

    private $_digist;
    private $_state;

    public function __construct($str) {
        $bin = $this->_str2bin($str);
        $len = strlen($str) * self::CHAR_ALIGNMENT;
        $bin[$len >> 5] |= 128 << ($len % 32);
        $bin[((($len + 64) >> 9) << 4) + 14] = $len;

        $this->_md5Init();
        $this->_update($bin);
        $this->_digist = $this->_bin2hex($this->_state);
    }

    /**
     * 公有方法
     * 获取信息摘要
     * @return string
     */
    public function getDigist() {
        return $this->_digist;
    }

    private function _bin2hex($bin) {
        $hex_tab = "0123456789abcdef";
        $str = "";
        for ($i = 0; $i < count($bin) * 4; $i++) {
            $str .= $hex_tab[($bin[$i >> 2] >> (($i % 4) * 8 + 4)) & 0xF] .
                    $hex_tab[($bin[$i >> 2] >> (($i % 4) * 8 )) & 0xF];
        }
        return $str;
    }

    private function _update($bin) {
        $bin_len = count($bin);
        for ($i = 0; $i < $bin_len; $i += 16) {
            $block = array();
            for ($j = 0; $j < 16; $j++) {
                $numa = !empty($block[$j]) ? $block[$j] : ($block[$j] = 0);
                //echo $numa;
                $num = !empty($bin[$i + $j]) ? $bin[$i + $j] : 0;
                $block[$j] = $numa + $num;
                //$block[$j] += !empty($bin[$i + $j]) ? $bin[$i + $j] : 0;
            }
            $this->_md5Transform($block);
            unset($block);
        }
    }

     /**
       * 初始化
       */
    private function _md5Init() {

        $this->_state[0] = intval(0x67452301);
        $this->_state[1] = intval(0xefcdab89);
        $this->_state[2] = intval(0x98badcfe);
        $this->_state[3] = intval(0x10325476);

        return TRUE;
    }

    private function _md5Transform($block) {
        $a = $this->_state[0];
        $b = $this->_state[1];
        $c = $this->_state[2];
        $d = $this->_state[3];

        $x = $block;

        /** Round 1 */
        MD5Tool::FF($a, $b, $c, $d, $x[0], MD5Tool::S11, 0xd76aa478); /* 1 */
        MD5Tool::FF($d, $a, $b, $c, $x[1], MD5Tool::S12, 0xe8c7b756); /* 2 */
        MD5Tool::FF($c, $d, $a, $b, $x[2], MD5Tool::S13, 0x242070db); /* 3 */
        MD5Tool::FF($b, $c, $d, $a, $x[3], MD5Tool::S14, 0xc1bdceee); /* 4 */
        MD5Tool::FF($a, $b, $c, $d, $x[4], MD5Tool::S11, 0xf57c0faf); /* 5 */
        MD5Tool::FF($d, $a, $b, $c, $x[5], MD5Tool::S12, 0x4787c62a); /* 6 */
        MD5Tool::FF($c, $d, $a, $b, $x[6], MD5Tool::S13, 0xa8304613); /* 7 */
        MD5Tool::FF($b, $c, $d, $a, $x[7], MD5Tool::S14, 0xfd469501); /* 8 */
        MD5Tool::FF($a, $b, $c, $d, $x[8], MD5Tool::S11, 0x698098d8); /* 9 */
        MD5Tool::FF($d, $a, $b, $c, $x[9], MD5Tool::S12, 0x8b44f7af); /* 10 */
        MD5Tool::FF($c, $d, $a, $b, $x[10], MD5Tool::S13, 0xffff5bb1); /* 11 */
        MD5Tool::FF($b, $c, $d, $a, $x[11], MD5Tool::S14, 0x895cd7be); /* 12 */
        MD5Tool::FF($a, $b, $c, $d, $x[12], MD5Tool::S11, 0x6b901122); /* 13 */
        MD5Tool::FF($d, $a, $b, $c, $x[13], MD5Tool::S12, 0xfd987193); /* 14 */
        MD5Tool::FF($c, $d, $a, $b, $x[14], MD5Tool::S13, 0xa679438e); /* 15 */
        MD5Tool::FF($b, $c, $d, $a, $x[15], MD5Tool::S14, 0x49b40821); /* 16 */

        /** Round 2 */
        MD5Tool::GG($a, $b, $c, $d, $x[1], MD5Tool::S21, 0xf61e2562); /* 17 */
        MD5Tool::GG($d, $a, $b, $c, $x[6], MD5Tool::S22, 0xc040b340); /* 18 */
        MD5Tool::GG($c, $d, $a, $b, $x[11], MD5Tool::S23, 0x265e5a51); /* 19 */
        MD5Tool::GG($b, $c, $d, $a, $x[0], MD5Tool::S24, 0xe9b6c7aa); /* 20 */
        MD5Tool::GG($a, $b, $c, $d, $x[5], MD5Tool::S21, 0xd62f105d); /* 21 */
        MD5Tool::GG($d, $a, $b, $c, $x[10], MD5Tool::S22, 0x2441453); /* 22 */
        MD5Tool::GG($c, $d, $a, $b, $x[15], MD5Tool::S23, 0xd8a1e681); /* 23 */
        MD5Tool::GG($b, $c, $d, $a, $x[4], MD5Tool::S24, 0xe7d3fbc8); /* 24 */
        MD5Tool::GG($a, $b, $c, $d, $x[9], MD5Tool::S21, 0x21e1cde6); /* 25 */
        MD5Tool::GG($d, $a, $b, $c, $x[14], MD5Tool::S22, 0xc33707d6); /* 26 */
        MD5Tool::GG($c, $d, $a, $b, $x[3], MD5Tool::S23, 0xf4d50d87); /* 27 */
        MD5Tool::GG($b, $c, $d, $a, $x[8], MD5Tool::S24, 0x455a14ed); /* 28 */
        MD5Tool::GG($a, $b, $c, $d, $x[13], MD5Tool::S21, 0xa9e3e905); /* 29 */
        MD5Tool::GG($d, $a, $b, $c, $x[2], MD5Tool::S22, 0xfcefa3f8); /* 30 */
        MD5Tool::GG($c, $d, $a, $b, $x[7], MD5Tool::S23, 0x676f02d9); /* 31 */
        MD5Tool::GG($b, $c, $d, $a, $x[12], MD5Tool::S24, 0x8d2a4c8a); /* 32 */

        /** Round 3 */
        MD5Tool::HH($a, $b, $c, $d, $x[5], MD5Tool::S31, 0xfffa3942); /* 33 */
        MD5Tool::HH($d, $a, $b, $c, $x[8], MD5Tool::S32, 0x8771f681); /* 34 */
        MD5Tool::HH($c, $d, $a, $b, $x[11], MD5Tool::S33, 0x6d9d6122); /* 35 */
        MD5Tool::HH($b, $c, $d, $a, $x[14], MD5Tool::S34, 0xfde5380c); /* 36 */
        MD5Tool::HH($a, $b, $c, $d, $x[1], MD5Tool::S31, 0xa4beea44); /* 37 */
        MD5Tool::HH($d, $a, $b, $c, $x[4], MD5Tool::S32, 0x4bdecfa9); /* 38 */
        MD5Tool::HH($c, $d, $a, $b, $x[7], MD5Tool::S33, 0xf6bb4b60); /* 39 */
        MD5Tool::HH($b, $c, $d, $a, $x[10], MD5Tool::S34, 0xbebfbc70); /* 40 */
        MD5Tool::HH($a, $b, $c, $d, $x[13], MD5Tool::S31, 0x289b7ec6); /* 41 */
        MD5Tool::HH($d, $a, $b, $c, $x[0], MD5Tool::S32, 0xeaa127fa); /* 42 */
        MD5Tool::HH($c, $d, $a, $b, $x[3], MD5Tool::S33, 0xd4ef3085); /* 43 */
        MD5Tool::HH($b, $c, $d, $a, $x[6], MD5Tool::S34, 0x4881d05); /* 44 */
        MD5Tool::HH($a, $b, $c, $d, $x[9], MD5Tool::S31, 0xd9d4d039); /* 45 */
        MD5Tool::HH($d, $a, $b, $c, $x[12], MD5Tool::S32, 0xe6db99e5); /* 46 */
        MD5Tool::HH($c, $d, $a, $b, $x[15], MD5Tool::S33, 0x1fa27cf8); /* 47 */
        MD5Tool::HH($b, $c, $d, $a, $x[2], MD5Tool::S34, 0xc4ac5665); /* 48 */

        /** Round 4 */
        MD5Tool::II($a, $b, $c, $d, $x[0], MD5Tool::S41, 0xf4292244); /* 49 */
        MD5Tool::II($d, $a, $b, $c, $x[7], MD5Tool::S42, 0x432aff97); /* 50 */
        MD5Tool::II($c, $d, $a, $b, $x[14], MD5Tool::S43, 0xab9423a7); /* 51 */
        MD5Tool::II($b, $c, $d, $a, $x[5], MD5Tool::S44, 0xfc93a039); /* 52 */
        MD5Tool::II($a, $b, $c, $d, $x[12], MD5Tool::S41, 0x655b59c3); /* 53 */
        MD5Tool::II($d, $a, $b, $c, $x[3], MD5Tool::S42, 0x8f0ccc92); /* 54 */
        MD5Tool::II($c, $d, $a, $b, $x[10], MD5Tool::S43, 0xffeff47d); /* 55 */
        MD5Tool::II($b, $c, $d, $a, $x[1], MD5Tool::S44, 0x85845dd1); /* 56 */
        MD5Tool::II($a, $b, $c, $d, $x[8], MD5Tool::S41, 0x6fa87e4f); /* 57 */
        MD5Tool::II($d, $a, $b, $c, $x[15], MD5Tool::S42, 0xfe2ce6e0); /* 58 */
        MD5Tool::II($c, $d, $a, $b, $x[6], MD5Tool::S43, 0xa3014314); /* 59 */
        MD5Tool::II($b, $c, $d, $a, $x[13], MD5Tool::S44, 0x4e0811a1); /* 60 */
        MD5Tool::II($a, $b, $c, $d, $x[4], MD5Tool::S41, 0xf7537e82); /* 61 */
        MD5Tool::II($d, $a, $b, $c, $x[11], MD5Tool::S42, 0xbd3af235); /* 62 */
        MD5Tool::II($c, $d, $a, $b, $x[2], MD5Tool::S43, 0x2ad7d2bb); /* 63 */
        MD5Tool::II($b, $c, $d, $a, $x[9], MD5Tool::S44, 0xeb86d391); /* 64 */

        /**
         * 注意，这里必须执行intval函数
         */
        $this->_state[0] = intval($this->_state[0] + $a);
        $this->_state[1] = intval($this->_state[1] + $b);
        $this->_state[2] = intval($this->_state[2] + $c);
        $this->_state[3] = intval($this->_state[3] + $d);
    }

    private function _str2bin($str) {
        $bin = array();
        $alignment = (1 << self::CHAR_ALIGNMENT) - 1;
        $len = strlen($str);

        for ($i = 0; $i < $len * self::CHAR_ALIGNMENT; $i += self::CHAR_ALIGNMENT) {
            $key = $i >> 5;
            $bin_num = !empty($bin[$key]) ? $bin[$key] : ($bin[$key] = 0);
            $bin[$key] |= ( ord($str[$i / self::CHAR_ALIGNMENT]) & $alignment) << ($i % 32);
        }

        return $bin;
    }

}

class MD5Tool {
    /** S11-S44原本是一个 4 * 4 的矩阵，在C实现中是用#define 实现的，
     * 这里作为类的常量表示，在各种对象间共享
     */
    const S11 = 7;
    const S12 = 12;
    const S13 = 17;
    const S14 = 22;

    const S21 = 5;
    const S22 = 9;
    const S23 = 14;
    const S24 = 20;

    const S31 = 4;
    const S32 = 11;
    const S33 = 16;
    const S34 = 23;

    const S41 = 6;
    const S42 = 10;
    const S43 = 15;
    const S44 = 21;

    /** F, G, H ,I 是4个基本的MD5函数，
     * 在C实现中，一般是用宏实现，这里我们以类方法的形式给出
     */
    public static function F($x, $y, $z) {
        return ($x & $y) | ((~$x) & $z);
    }

    public static function G($x, $y, $z) {
        return ($x & $z) | ($y & (~$z));
    }

    public static function H($x, $y, $z) {
        return $x ^ $y ^ $z;
    }

    public static function I($x, $y, $z) {
        return $y ^ ($x | (~$z));
    }

    /**
     * 左移N位
     * @param type $x
     * @param type $n
     * @return type
     */
    public static function ROTATE_LEFT($x, $n) {
        return ($x << $n) | self::URShift($x, (32 - $n));
    }

    /**
     * PHP无符号右移
     * @param type $x
     * @param type $bits
     * @return type
     */
    public static function URShift($x, $bits) {
        /** 转换成代表二进制数字的字符串 */
        $bin = decbin($x);
        $len = strlen($bin);

        /** 字符串长度超出则截取底32位，长度不够，则填充高位为0到32位  */
        if ($len > 32) {
            $bin = substr($bin, $len - 32, 32);
        } elseif ($len < 32) {
            $bin = str_pad($bin, 32, '0', STR_PAD_LEFT);
        }

        /** 取出要移动的位数，并在左边填充0  */
        return bindec(str_pad(substr($bin, 0, 32 - $bits), 32, '0', STR_PAD_LEFT));
    }

    /**
     * FF,GG,HH和II将调用F,G,H,I进行近一步变换
     * 其中FF,GG,HH和II分别为四轮转移调用
     *
     * 注意: 在PHP中，这里使用了引用返回，第一个元素
     * 并且所有的返回值必须执行intval强制转换为整形，否则最终可能会被PHP自动转换
     */
    public static function FF(&$a, $b, $c, $d, $x, $s, $ac) {
        $a += self::F($b, $c, $d) + ($x) + $ac;
        $a = self::ROTATE_LEFT($a, $s);
        $a = intval($a + $b);
    }

    public static function GG(&$a, $b, $c, $d, $x, $s, $ac) {
        $a += self::G($b, $c, $d) + ($x) + $ac;
        $a = self::ROTATE_LEFT($a, $s);
        $a = intval($a + $b);
    }

    public static function HH(&$a, $b, $c, $d, $x, $s, $ac) {
        $a += self::H($b, $c, $d) + ($x) + $ac;
        $a = self::ROTATE_LEFT($a, $s);
        $a = intval($a + $b);
    }

    public static function II(&$a, $b, $c, $d, $x, $s, $ac) {
        $a += self::I($b, $c, $d) + ($x) + $ac;
        $a = self::ROTATE_LEFT($a, $s);
        $a = intval($a + $b);
    }

}

?>
