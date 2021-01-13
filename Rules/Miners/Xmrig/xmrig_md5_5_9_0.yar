import "hash"

private rule tar_gz_5_9_0
{
	meta:
		description = "xmrig-5.9.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "b63ead42823ae63c93ac401e38937323"
}

private rule xmrig_5_9_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "d351de486d4bb4e80316e1524682c602"
}

private rule xmrig_notls_5_9_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "187ed1d112e4a9dff0241368f2868615"
}


rule xmrig_md5_5_9_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_9_0 or xmrig_5_9_0 or xmrig_notls_5_9_0
}
