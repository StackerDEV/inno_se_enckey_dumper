# Inno Setup ScriptEngine runtime encryption key dumper PoC

* When devs embed cryptographic secrets in their compressed program that gets extracted at runtime.

* It's never a good idea, it's really easy to find the decompressed IFPS ROPS bytecode after the child process is launched.

* This shitty example will show a nasty trick on how to extract the embedded encryption password at runtime.

## Test enviroment

Sample Size      | Ansi           | Unicode           |  Tested version  |
---------------- | ---------------| ----------------- | ---------------- |
2                | Working        | Not working       |  5.6.1 -> 6.0.3  |

IDE: VS 2015, toolkit v140.

Block chart (not correct,  prototype). 

![screendump blockchart](https://github.com/StackerDEV/inno_se_enckey_dumper/blob/main/blockchart.png?raw=true)

Ansi sample:

![screendump screendump](https://github.com/StackerDEV/inno_se_enckey_dumper/blob/main/screendump.png?raw=true)


**Notes:**
Credits to MinHook devs, and other devs for their functions.


## License

> None
