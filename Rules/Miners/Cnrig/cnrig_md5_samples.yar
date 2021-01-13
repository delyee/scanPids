// 

import "hash"

rule cnrig_md5_samples_1: mining md5 cnrig
{
	meta:
		description = ""
		author = "delyee"
        date = "10.05.2019"
	condition:
		hash.md5(0, filesize) == "6485afca3bfd332158593b867eb5190c"
}