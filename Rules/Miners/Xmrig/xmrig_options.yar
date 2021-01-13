rule XmrigCnrigOptions: mining xmrig cnrig
{
    meta:
        description = "cli options"
        author = "delyee"
        date = "18.04.2020"
    strings:
        $ = "--donate-level" ascii
        $ = "--nicehash" ascii
        $ = "--algo" ascii
        $ = "--threads" ascii
        $ = "--cpu-max-threads-hint" ascii
        $ = "xmrig" ascii fullword
    condition:
        3 of them
}