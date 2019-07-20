# Galaxy Socket

## Intro

Galaxy Socket is a lightweight secured proxy, it's written by pure c.
This is me first time use c write something.

Current version: 1.0.0

## Features

    gsserver: Galaxy Socket Server.

    gsgenkey: generate the secret key.

    gsred   : forwarding the tcp/udp for iptables, udp need TPROXY.

    gssocks5: local socks5 server.

    gsdns   : local dns server.

## Dependencies
* linux(epoll)
* pthread
* libz
* libiniparser
* openssl

## Usage

    gs[server|red|socks5|dns] INI_FILE

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
