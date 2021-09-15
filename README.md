# 这是一个基于php编写的密码验证类库

### 使用说明
```php
<?php
require './vendor/autoload.php';

use Recallg\Makepass\Verification;
$Makepass = new Verification();

$password = '123456';
$str = $Makepass->encryption($password);

echo $str."</br>";

$res = $Makepass->decryption("123456", $str);

if ($res)
{

    echo '密码正确';

}else{

    echo '密码错误';

}
```
