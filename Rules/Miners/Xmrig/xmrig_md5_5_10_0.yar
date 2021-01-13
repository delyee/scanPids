import "hash"

private rule tar_gz_5_10_0
{
	meta:
		description = "xmrig-5.10.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "416079fd0c7b45307556198f3f67754d"
}

private rule xmrig_5_10_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "3939395192972820ce2cf99db0c239d7"
}

private rule xmrig_notls_5_10_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "0456ef39240c75e0862b30419d4c6359"
}


rule xmrig_md5_5_10_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_10_0 or xmrig_5_10_0 or xmrig_notls_5_10_0
}
