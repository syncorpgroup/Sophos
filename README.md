# Sophos

=======

Introduction:
-----------
Library to control a Sophos Firewall XG via API.
The idea here is construct a HTTP GET in XML form-based as mentioned on API Sophos link:
https://docs.sophos.com/nsg/sophos-firewall/18.0/API/index.html
HOLA SUSSYYY
Usage:
-----------
Declare user, pass and IP to connect a Firewall XG.
By deault, it use IP Address 172.16.16.16 and port 4444.
sophosxg('user','pass')

There are three mayor method group here: GET, SET, DEL.

    set_xxx(arguments) : Method to set information on Firewall XG
    get_xxx()          : Method to obtain information from Firewall XG.
    del_xxx(argument)  : Method to delete information on Firewall XG

**Examples:**
```
    from sophoslib import sophosxg
    fw = sophosxg('apiadmin','SYNCORP_Passw0rd')
    fw.set_iphost('Test1','5.5.5.5')
    fw.get_iphost()
    fw.del_iphost('Test1')
```
For more information in how to activate the API for Sophos XG Firewall, check:
https://support.sophos.com/support/s/article/KB-000038263?language=en_US

__author__ = "Kevin Anel Hernandez Ruiz"

__copyright__ = "Copyleft 2020, The SYNCORP Project."

__credits__ = ["Kevin Anel Hernandez Ruiz"]

__license__ = "GPL"

__version__ = "1.0.0"

__maintainer__ = "Kevin Hernandez"

__email__ = "kevin@syncorpgroup.com"

__status__ = "Development"

__GITHUB__ = "https://github.com/kdemenx"

__webpage__ = "https://www.syncorpgroup.com"
