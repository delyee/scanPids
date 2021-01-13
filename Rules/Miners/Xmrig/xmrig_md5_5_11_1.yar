// по тестам, md5 быстрее sha*

import "hash"

private rule tar_gz_5_11_1
{
	meta:
		description = "xmrig-5.11.1-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "820022ba985b4d21637bf6d3d1e53001"
}

private rule xmrig_5_11_1
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "0090962752b93454093239f770628006"
}

private rule xmrig_notls_5_11_1
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "54158be61b8011a10d1a94432ead208c"
}


rule xmrig_md5_5_11_1: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_11_1 or xmrig_5_11_1 or xmrig_notls_5_11_1
}
