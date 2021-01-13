import "hash"

rule xmrig_md5_samples_1: mining md5 xmrig
{
	meta:
		description = ""
		author = "delyee"
        date = "10.05.2019"
	condition:
		hash.md5(0, filesize) == "6f2a2ff340fc1307b65174a3451f8c9a"
}
