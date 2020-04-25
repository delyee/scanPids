/*
https://github.com/fireice-uk/xmr-stak
https://github.com/hyc/cpuminer-multi
https://github.com/xmrig/xmrig

// 7f 45 4c 46
*/

import "elf"

rule MiningPools: mining
{
    meta:
        description = ""
        author = "delyee"
        date = "18-04-2020"
    strings:
        $ = "nicehash.com" ascii fullword
        $ = ".monero.org" ascii fullword
        $ = ".poolto.be" ascii fullword
        $ = "dwarfpool.com" ascii fullword

        $ = "2miners.com" ascii fullword
        $ = "antpool.com" ascii fullword
        $ = "bohemianpool.com" ascii fullword
        $ = "c3pool.com" ascii fullword
        $ = "cnpool.cc" ascii fullword
        $ = "coinfoundry.org" ascii fullword
        $ = "crypto-pool.fr" ascii fullword
        $ = "cryptonote.club" ascii fullword
        $ = "cryptonote.social" ascii fullword
        $ = "dxpool.com" ascii fullword
        $ = "f2pool.com" ascii fullword
        $ = "fairhash.org" ascii fullword
        $ = "fastpool.xyz" ascii fullword
        $ = "flooder.org" ascii fullword
        $ = "fungibly.xyz" ascii fullword
        $ = "gntl.co.uk" ascii fullword
        $ = "hashcity.org" ascii fullword
        $ = "hashing.mine.nu" ascii fullword
        $ = "hashpool.cc" ascii fullword
        $ = "hashvault.pro" ascii fullword
        $ = "hellominer.com" ascii fullword
        $ = "herominers.com" ascii fullword
        $ = "luxor.tech" ascii fullword
        $ = "majanetwork.com" ascii fullword
        $ = "miner.rocks" ascii fullword
        $ = "minergalaxy.com" ascii fullword
        $ = "minergate.com" ascii fullword
        $ = "miners.pro" ascii fullword
        $ = "minexmr.com" ascii fullword
        $ = "miningpool.fun" ascii fullword
        $ = "miningpoolhub.com" ascii fullword
        $ = "monerohash.com" ascii fullword
        $ = "moneroocean.stream" ascii fullword
        $ = "monerop.com" ascii fullword
        $ = "muxdux.com" ascii fullword
        $ = "mymoneropool.com" ascii fullword
        $ = "mypool.online" ascii fullword
        $ = "nanopool.org" ascii fullword
        $ = "newpool.cool" ascii fullword
        $ = "okex.com" ascii fullword
        $ = "omine.org" ascii fullword
        $ = "pool-moscow.ru" ascii fullword
        $ = "pool-pay.com" ascii fullword
        $ = "pool2mine.com" ascii fullword
        $ = "pooldd.com" ascii fullword
        $ = "ragerx.lol" ascii fullword
        $ = "semipool.com" ascii fullword
        $ = "skypool.org" ascii fullword
        $ = "snowmining.com" ascii fullword
        $ = "solopool.org" ascii fullword
        $ = "spookypool.nl" ascii fullword
        $ = "supportxmr.com" ascii fullword
        $ = "viabtc.com" ascii fullword
        $ = "xmr.pt" ascii fullword
        $ = "xmrpool.eu" ascii fullword
        $ = "xmrpool.net" ascii fullword
        $ = "xzrm.com" ascii fullword
        $ = "zergpool.com" ascii fullword

    condition:
        any of them
}


rule MinersOptions: mining
{
    meta:
        description = ""
        author = "delyee"
        date = "18.04.2020"
    strings:
        $ = "--donate-level" ascii
        $ = "--nicehash" ascii
    condition:
        any of them
}

rule MinersStings: mining
{
    meta:
        description = ""
        author = "delyee"
        date = "18.04.2020"
    strings:
        $ = "hashrate" ascii
        $ = "monero" ascii
        //$ = "xmr" fullword ascii
        $ = "stratum+tcp" ascii
        $ = "stratum+udp" ascii
    condition:
        any of them
}

/*
rule GenericMiner: miner
{
    meta:
        description = ""
        author = "delyee"
        date = "16.04.2020"
    condition:
        elf.entry_point and any of (MiningPools, MinersOptions, MinersStings)
}
*/

// $s7 = "xmrig" fullword nocase ascii

