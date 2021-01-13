rule XmrigConfig: json mining xmrig
{
    meta:
        description = "xmrig config.json"
        author = "delyee"
        date = "07.05.2020"
    strings:
        $ = "\"worker-id\":" ascii
        $ = "\"randomx\":" ascii
        $ = "\"donate-level\":" ascii
        $ = "\"rig-id\":" ascii
        $ = "\"donate-over-proxy\":" ascii
    condition:
        3 of them
}