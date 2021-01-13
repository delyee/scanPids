import "hash"

private rule tar_gz_5_11_0
{
	meta:
		description = "xmrig-5.11.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "abf7feaf1e456c0fc6e8f1e40af9211c"
}

private rule xmrig_5_11_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "56aec7d8d2aba5ba2b82930408f0b5d3"
}

private rule xmrig_notls_5_11_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "9a5c0a5d960b676ba4db535f71ee7cef"
}


rule xmrig_md5_5_11_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_11_0 or xmrig_5_11_0 or xmrig_notls_5_11_0
}
