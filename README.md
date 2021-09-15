# 一个基于php的密码验证类库

## 使用说明

$password = '123456';

$str = encryption($password);
echo $str."</br>";

$res = decryption("123456", $str);

if ($res)
{

    echo '密码正确';

}else{

    echo '密码错误';

}
