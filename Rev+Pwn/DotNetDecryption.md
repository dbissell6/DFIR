.NET obfuscated strings can be dynamically deobfuscated with powershell.

Below is a simple example of obfuscated strings and a function do decrypt them.


<img width="1391" height="894" alt="image" src="https://github.com/user-attachments/assets/435739e3-a594-4146-a072-058a861b6b66" />

Making sure we have powershell version 7 as pwsh. We can run the following script. 

```
$type = $asm.GetType("StringLabDemo.StringDecryptor")
$count = $type::Count()

for ($i = 0; $i -lt $count; $i++) {
    $result = $type::ResolveString($i)
    Write-Host "ID $i -> $result"
}
```

<img width="996" height="204" alt="image" src="https://github.com/user-attachments/assets/9d3557e3-4417-4208-8e0f-ee4b0a84857a" />







