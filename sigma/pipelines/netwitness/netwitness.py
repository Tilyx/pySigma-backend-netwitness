from re import M
from sigma.processing.transformations import FieldMappingTransformation, DetectionItemFailureTransformation
from sigma.processing.conditions import LogsourceCondition, ExcludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

"""
List Windows Field not support:
Action
Address
AllowedToDelegateTo
AttributeLDAPDisplayName
AuditPolicyChanges
AuditSourceName
CallTrace
Caption
CertThumbprint
Channel
ClassName
Company
ContextInfo
CurrentDirectory
Description
DestinationIsIpv6
Device
DeviceDescription
DeviceName
Details
FileVersion
HiveName
HostVersion
Initiated
KeyLength
LayerRTID
Level
LocalName
LogonId
NewName
PipeName
ParentUser
PasswordLastSet
PossibleCause
PrivilegeList
Product
Properties
Provider
ProviderName
Provider_Name
QNAME
Query
QueryName
QueryResults
QueryStatus
RemoteAddress
Service
SearchFilter
ServerName
ServicePrincipalNames
ServiceStartType
ServiceType
SidHistory
Signed
Source_Name
StartAddress
StartFunction
StartModule
State
SubjectDomainName
SubjectLogonId
SubjectUserSid
TargetLogonId
TargetName
TicketEncryptionType
TicketOptions
Type
User
UserName
Value
TargetUserSid
TargetSid
ObjectServer
OldUacValue
Origin
ObjectValueName
OldTargetUserName
AuthenticationPackageName
GrantedAccess
Hashes
HostApplication
IntegrityLevel
Keywords
MachineName
Message
NewTargetUserName
OriginalFilename
ParentCommandLine
Path
Payload
ScriptBlockText
SourceImage
TargetFilename
TargetImage
param1
param2
processPath
sha1
c-uri
c-uri-extension
c-useragent
c-uri-query
cs-method
r-dns
ClientIP
url.query
resource.URL
User
md5
sha256
"""

netwitness_windows_event = {
    "AccessList": "accesses",
    "dst": "ip.dst",
    "dst_ip": "ip.dst",
    "src": "ip.src",
    "src_ip": "ip.src",
    "c-ip": "ip.src",
    "cs-ip": "ip.src",
    "SourceAddress": "ip.src",
    "SourcePort": "ip.srcport",
    "DestinationPort": "ip.dstport",
    "TargetPort": "ip.dstport",
    "TargetServerName": "ip.dst",
    "EventID": "reference.id",
    "EventId": "reference.id",
    "NewProcessName": "process",
    "LogonType": "logon.type",
    "AccountName": "user.dst",
    "c-uri-extension": "extension",
    "c-useragent": "user.agent",
    "r-dns": "alias.host",
    "DestinationHostname": "alias.host",
    "cs-host": "alias.host",
    "c-uri-query": "web.page",
    "c-uri": "web.page",
    "cs-method": "action",
    "cs-cookie": "web.cookie",
    "SubjectUserName": "user.dst",
    "CommandLine": "param",
    "Commandline": "param",
    "ComputerName": "event.computer",
    "LogonProcessName": "process",
    "TargetUserName": "user.dst",
    "CallerProcessName": "process",
    "WorkstationName": "host.src",
    "Image": "process",
    "DestAddress": "ip.dst",
    "DestPort": "ip.dstport",
    "Destination": "ip.dst",
    "DestinationIp": "ip.dst",
    "TargetObject": "obj.name",
    "FailureCode": "result.code",
    "HostName": "alias.host",
    "ImagePath": "filename",
    "IpAddress": "ip.src",
    "ObjectName": "obj.name",
    "ObjectType": "obj.type",
    "ProcessName": "process",
    "OriginalFileName": "process",
    "OriginalName": "filename",
    "ParentImage": "process.src",
    "ProcessId": "process.id.val",
    "ProcessName": "process",
    "SamAccountName": "user.src",
    "ServiceFileName": "filename",
    "ServiceName": "service.name",
    "Service": "service.name",
    "ShareName": "obj.name",
    "SubjectUserName": "user.dst",
    "TargetObject": "obj.name",
    "TaskName": "service.name",
    "User": "user.dst",
    "ParentProcessId": "parent.pid.val",
    "RelativeTargetName": "filename",
    "AttributeValue": "param",
    "EventType": "obj.type",
    "Status": "result.code",
    "Workstation": "host.src",
    "WorkstationName": "host.src",
    "ObjectClass": "obj.type"
}

def netwitness_windows():
    return ProcessingPipeline(
        name="RSA Netwitness & RSA Netwitness EPL field mapping",
        priority=20,
        items= [
            ProcessingItem(
                identifier="Qradar_savedsearches_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The RSA Netwitness & RSA Netwitness EPL Sigma backend supports only the following fields for windows log source, future will be update for Sysmon logsource and Linux"),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ],
                rule_condition_linking=any,
                detection_item_conditions=[
                    ExcludeFieldCondition(
                        fields = netwitness_windows_event.keys()
                    )
                ]
            ),
            ProcessingItem(     # Some optimizations searching for characteristic keyword for specific log sources
                identifier="netwitness_windows_event_logs",
                transformation=FieldMappingTransformation(netwitness_windows_event),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ]
            )

        ]
    )