# T-Pot Thesis Research Edition

A research-focused multi-honeypot cyber threat monitoring and analysis environment developed for thesis experimentation.

Based on [T-Pot](https://github.com/telekom-security/tpotce) 24.04.1 by Deutsche Telekom Security.

## Thesis-Specific Work

The thesis edition is a configuration layer on top of T-Pot. The honeypots, Elastic stack, Attack Map and other components are T-Pot's own work, unchanged. The additions of this project are:

- Research-focused Docker Compose deployment ([`docker-compose.thesis.yml`](docker-compose.thesis.yml))
- Selected honeypot/protocol exposure
- Thesis landing page ([`thesis/nginx/index.html`](thesis/nginx/index.html))
- Thesis Overview Kibana dashboard ([`thesis/kibana/`](thesis/kibana/))
- Attack Map integration
- Attack Map end-to-end validation procedure, using T-Pot's own `attackmap_pipeline_test.sh`
- Elasticvue integration
- Suricata, FATT and p0f integration
- Research-oriented visualization
- Protocol-specific monitoring
- Thesis data collection and analysis configuration

### Honeypots and exposed protocols

| Honeypot | Protocols (host ports) |
|---|---|
| Cowrie | SSH (22), Telnet (23) |
| DDoSPot | DNS (53/udp), NTP (123/udp) |
| Dionaea | FTP (21), SMB (445), MySQL (3306) |
| Mailoney | SMTP (25) |
| RDPHoneypot | RDP (3389) |
| SentryPeer | SIP (5060 tcp/udp) |
| Snare/Tanner | HTTP (80) |

Network monitoring: Suricata, FATT, p0f. Analysis: Elasticsearch, Logstash, Kibana, Attack Map, Elasticvue, behind NGINX with basic authentication (port 64297).

### Getting started

1. `cp env.example .env`, then set the values T-Pot requires there (for example the web user, see `genuser.sh`). `.env` is intentionally not part of this repository.
2. Start the thesis stack: `docker compose -f docker-compose.thesis.yml up`
3. Once Kibana is up, import the thesis dashboard: `thesis/kibana/import_thesis_dashboard.sh`

Please validate the deployment on your own host before relying on it: the configuration is prepared for thesis experiments, and runtime behaviour depends on the target system.

## Attribution and License

- This repository is a modified version of T-Pot 24.04.1 by Deutsche Telekom Security, [telekom-security/tpotce](https://github.com/telekom-security/tpotce). It is **not** the original and is not affiliated with or endorsed by its authors.
- T-Pot is licensed under the GNU General Public License v3.0; this repository is distributed under the same license, see [`LICENSE`](LICENSE). Copyright and license notices of T-Pot and its third-party components are kept unchanged, see [`CITATION.cff`](CITATION.cff) and the *Licenses* and *Credits* sections below, which are copied unchanged from the T-Pot README.
- The T-Pot commit history and its contributor list are intentionally not part of this repository's history. The full history and authorship are in the upstream repository.

---

## Third-Party Licenses and Credits (copied unchanged from the T-Pot README)

The complete T-Pot documentation (installation, operation, architecture) is in the [upstream README](https://github.com/telekom-security/tpotce/blob/master/README.md).

# Licenses
The software that T-Pot is built on uses the following licenses.
<br>GPLv2:
[conpot](https://github.com/mushorg/conpot/blob/master/LICENSE.txt),
[galah](https://github.com/0x4D31/galah?tab=Apache-2.0-1-ov-file#readme),
[dionaea](https://github.com/DinoTools/dionaea/blob/master/LICENSE),
[honeytrap](https://github.com/armedpot/honeytrap/blob/master/LICENSE),
[suricata](https://suricata.io/features/open-source/)
<br>GPLv3:
[adbhoney](https://github.com/huuck/ADBHoney),
[elasticpot](https://gitlab.com/bontchev/elasticpot/-/blob/master/LICENSE),
[ewsposter](https://github.com/telekom-security/ewsposter),
[log4pot](https://github.com/thomaspatzke/Log4Pot/blob/master/LICENSE),
[fatt](https://github.com/0x4D31/fatt/blob/master/LICENSE),
[heralding](https://github.com/johnnykv/heralding/blob/master/LICENSE.txt),
[ipphoney](https://gitlab.com/bontchev/ipphoney/-/blob/master/LICENSE),
[miniprint](https://github.com/sa7mon/miniprint?tab=GPL-3.0-1-ov-file#readme),
[redishoneypot](https://github.com/cypwnpwnsocute/RedisHoneyPot/blob/main/LICENSE),
[rdphoneypot](https://gitlab.com/bontchev/rdphoneypot/-/blob/master/LICENSE),
[sentrypeer](https://github.com/SentryPeer/SentryPeer/blob/main/LICENSE.GPL-3.0-only),
[snare](https://github.com/mushorg/snare/blob/main/LICENSE),
[tanner](https://github.com/mushorg/snare/blob/main/LICENSE)
<br>Apache 2 License:
[cyberchef](https://github.com/gchq/CyberChef/blob/master/LICENSE),
[dicompot](https://github.com/nsmfoo/dicompot/blob/master/LICENSE),
[elasticsearch](https://github.com/elastic/elasticsearch/blob/master/LICENSE.txt),
[go-pot](https://github.com/ryanolee/go-pot?tab=License-1-ov-file#readme),
[h0neytr4p](https://github.com/pbssubhash/h0neytr4p?tab=Apache-2.0-1-ov-file#readme),
[logstash](https://github.com/elastic/logstash/blob/main/LICENSE.txt),
[kibana](https://github.com/elastic/kibana/blob/main/LICENSE.txt),
[docker](https://github.com/moby/moby/blob/master/LICENSE)
<br>MIT license:
[autoheal](https://github.com/willfarrell/docker-autoheal?tab=MIT-1-ov-file#readme),
[beelzebub](https://github.com/beelzebub-labs/beelzebub?tab=MIT-1-ov-file#readme),
[ciscoasa](https://github.com/Cymmetria/ciscoasa_honeypot/blob/master/LICENSE),
[ddospot](https://github.com/aelth/ddospot/blob/master/LICENSE),
[elasticvue](https://github.com/cars10/elasticvue/blob/master/LICENSE),
[glutton](https://github.com/mushorg/glutton/blob/main/LICENSE),
[hellpot](https://github.com/yunginnanet/HellPot/blob/main/LICENSE),
[honeyaml](https://github.com/mmta/honeyaml?tab=MIT-1-ov-file#readme),
[maltrail](https://github.com/stamparm/maltrail/blob/master/LICENSE)
<br>Unlicense:
[endlessh](https://github.com/skeeto/endlessh/blob/master/UNLICENSE)
<br>Other:
[citrixhoneypot](https://github.com/MalwareTech/CitrixHoneypot#licencing-agreement-malwaretech-public-licence),
[cowrie](https://github.com/cowrie/cowrie/blob/main/LICENSE.rst),
[mailoney](https://github.com/phin3has/mailoney),
[Elastic License](https://www.elastic.co/licensing/elastic-license),
[Wordpot](https://github.com/gbrindisi/wordpot)
<br>AGPL-3.0:
[honeypots](https://github.com/qeeqbox/honeypots/blob/main/LICENSE)
<br>[Public Domain (CC)](https://creativecommons.org/publicdomain/zero/1.0/):
[Harvard Dataverse](https://dataverse.harvard.edu/dataverse/harvard/?q=dicom) 
<br><br>

# Credits
Without open source and the development community we are proud to be a part of, T-Pot would not have been possible! Our thanks are extended but not limited to the following people and organizations:
<br><br>

## The developers and development communities of

* [adbhoney](https://github.com/huuck/ADBHoney/graphs/contributors),
[beelzebub](https://github.com/beelzebub-labs/beelzebub/graphs/contributors),
[ciscoasa](https://github.com/Cymmetria/ciscoasa_honeypot/graphs/contributors),
[citrixhoneypot](https://github.com/MalwareTech/CitrixHoneypot/graphs/contributors),
[conpot](https://github.com/mushorg/conpot/graphs/contributors),
[cowrie](https://github.com/cowrie/cowrie/graphs/contributors),
[ddospot](https://github.com/aelth/ddospot/graphs/contributors),
[dicompot](https://github.com/nsmfoo/dicompot/graphs/contributors),
[dionaea](https://github.com/DinoTools/dionaea/graphs/contributors),
[docker](https://github.com/moby/moby/graphs/contributors),
[elasticpot](https://gitlab.com/bontchev/elasticpot/-/project_members),
[elasticsearch](https://github.com/elastic/elasticsearch/graphs/contributors),
[elasticvue](https://github.com/cars10/elasticvue/graphs/contributors),
[endlessh](https://github.com/skeeto/endlessh/graphs/contributors),
[ewsposter](https://github.com/armedpot/ewsposter/graphs/contributors),
[fatt](https://github.com/0x4D31/fatt/graphs/contributors),
[galah](https://github.com/0x4D31/galah/graphs/contributors),
[glutton](https://github.com/mushorg/glutton/graphs/contributors),
[go-pot](https://github.com/ryanolee/go-pot/graphs/contributors),
[h0neytr4p](https://github.com/pbssubhash/h0neytr4p/graphs/contributors),
[hellpot](https://github.com/yunginnanet/HellPot/graphs/contributors),
[heralding](https://github.com/johnnykv/heralding/graphs/contributors),
[honeyaml](https://github.com/mmta/honeyaml/graphs/contributors),
[honeypots](https://github.com/qeeqbox/honeypots/graphs/contributors),
[honeytrap](https://github.com/armedpot/honeytrap/graphs/contributors),
[ipphoney](https://gitlab.com/bontchev/ipphoney/-/project_members),
[kibana](https://github.com/elastic/kibana/graphs/contributors),
[logstash](https://github.com/elastic/logstash/graphs/contributors),
[log4pot](https://github.com/thomaspatzke/Log4Pot/graphs/contributors),
[mailoney](https://github.com/phin3has/mailoney),
[maltrail](https://github.com/stamparm/maltrail/graphs/contributors),
[medpot](https://github.com/schmalle/medpot/graphs/contributors),
[miniprint](https://github.com/sa7mon/miniprint/graphs/contributors),
[p0f](https://lcamtuf.coredump.cx/p0f3/),
[redishoneypot](https://github.com/cypwnpwnsocute/RedisHoneyPot/graphs/contributors),
[rdphoneypot](https://gitlab.com/bontchev/rdphoneypot/-/project_members),
[sentrypeer](https://github.com/SentryPeer/SentryPeer/graphs/contributors),
[spiderfoot](https://github.com/smicallef/spiderfoot),
[snare](https://github.com/mushorg/snare/graphs/contributors),
[tanner](https://github.com/mushorg/tanner/graphs/contributors),
[suricata](https://github.com/OISF/suricata/graphs/contributors),
[wordpot](https://github.com/gbrindisi/wordpot)
<br><br>

## **The following companies and organizations**
* [docker](https://www.docker.com/),
[elastic.io](https://www.elastic.co/),
[honeynet project](https://www.honeynet.org/)
<br><br>

## **And of course ***YOU*** for joining the community!**
<br>
