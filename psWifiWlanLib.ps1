echo @"
ConvertFrom-StringData @'
    ErrorOpeningHandle   = Error opening WiFi handle. Message {0}
    HandleClosed         = Handle successfully closed.
    ErrorClosingHandle   = Error closing handle. Message {0}
    ErrorGettingProfile  = Error getting profile info. Error code: {0}
    ProfileNotFound      = Profile {0} not found. Note ProfileName is case sensitive.
    ErrorDeletingProfile = Error deleting profile. Message {0}
    ShouldProcessDelete  = Deletion of profile {0}
    ErrorWlanConnect     = Error connecting to {0} : {1}
    SuccessWlanConnect   = Successfully connected to {0} : {1}
    ErrorReasonCode      = Failed to format reason code. Error message: {0}
    ErrorFreeMemory      = Failed to free memory. Error message: {0}
    ErrorGetAvailableNetworkList = Error invoking WlanGetAvailableNetworkList. Message {0}
    ErrorWiFiInterfaceNotFound = Wi-Fi interface not found on the system.
    ErrorNotWiFiAdapter  = Adapter with name: {0} is not a WiFi capable.
    ErrorNoWiFiAdaptersFound = No wifi interfaces found.
    ErrorMoreThanOneInterface = More than one Wi-Fi interface found. Please specify a specific interface.
    ErrorNeedSingleAdapterName = More than one Wi-Fi adapter found.  Please specify a single adapter name.
    ErrorFailedWithExitCode = Failed with exit code {0}.
'@
"@| Out-File $env:TEMP\WiFiProfileManagement.strings.psd1 -Force

$script:localizedData = Import-LocalizedData -BaseDirectory "$env:TEMP" -FileName WiFiProfileManagement.strings.psd1


$WlanGetProfileListSig = @'

[DllImport("wlanapi.dll")]
public static extern uint WlanOpenHandle(
    [In] UInt32 clientVersion,
    [In, Out] IntPtr pReserved,
    [Out] out UInt32 negotiatedVersion,
    [Out] out IntPtr clientHandle
);

[DllImport("Wlanapi.dll")]
public static extern uint WlanCloseHandle(
    [In] IntPtr ClientHandle,
    IntPtr pReserved
);

[DllImport("wlanapi.dll", SetLastError = true, CallingConvention=CallingConvention.Winapi)]
public static extern uint WlanGetProfileList(
    [In] IntPtr clientHandle,
    [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
    [In] IntPtr pReserved,
    [Out] out IntPtr profileList
);

[DllImport("wlanapi.dll")]
public static extern uint WlanGetProfile(
    [In]IntPtr clientHandle,
    [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
    [In, MarshalAs(UnmanagedType.LPWStr)] string profileName,
    [In, Out] IntPtr pReserved,
    [Out, MarshalAs(UnmanagedType.LPWStr)] out string pstrProfileXml,
    [In, Out, Optional] ref uint flags,
    [Out, Optional] out uint grantedAccess
);

[DllImport("wlanapi.dll")]
public static extern uint WlanDeleteProfile(
    [In]IntPtr clientHanle,
    [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
    [In, MarshalAs(UnmanagedType.LPWStr)] string profileName,
    [In, Out] IntPtr pReserved
);

[DllImport("wlanapi.dll", EntryPoint = "WlanFreeMemory")]
public static extern void WlanFreeMemory(
    [In] IntPtr pMemory
);

[DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint WlanSetProfile(
    [In] IntPtr clientHanle,
    [In] ref Guid interfaceGuid,
    [In] uint flags,
    [In] IntPtr ProfileXml,
    [In, Optional] IntPtr AllUserProfileSecurity,
    [In] bool Overwrite,
    [In, Out] IntPtr pReserved,
    [In, Out]ref IntPtr pdwReasonCode
);

[DllImport("wlanapi.dll",SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint WlanReasonCodeToString(
    [In] uint reasonCode,
    [In] uint bufferSize,
    [In, Out] StringBuilder builder,
    [In, Out] IntPtr Reserved
);

[DllImport("Wlanapi.dll", SetLastError = true)]
public static extern uint WlanGetAvailableNetworkList(
    [In] IntPtr hClientHandle,
    [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
    [In] uint dwFlags,
    [In] IntPtr pReserved,
    [Out] out IntPtr ppAvailableNetworkList
);

[DllImport("Wlanapi.dll", SetLastError = true)]
public static extern uint WlanConnect(
    [In] IntPtr hClientHandle,
    [In] ref Guid interfaceGuid,
    [In] ref WLAN_CONNECTION_PARAMETERS pConnectionParameters,
    [In, Out] IntPtr pReserved
);

[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
public struct WLAN_CONNECTION_PARAMETERS
{
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    public string strProfile;
    public DOT11_SSID[] pDot11Ssid;
    public DOT11_BSSID_LIST[] pDesiredBssidList;
    public DOT11_BSS_TYPE dot11BssType;
    public uint dwFlags;
}

public struct DOT11_BSSID_LIST
{
    public NDIS_OBJECT_HEADER Header;
    public ulong uNumOfEntries;
    public ulong uTotalNumOfEntries;
    public IntPtr BSSIDs;
}

public struct NDIS_OBJECT_HEADER
{
    public byte Type;
    public byte Revision;
    public ushort Size;
}

public struct WLAN_PROFILE_INFO_LIST
{
    public uint dwNumberOfItems;
    public uint dwIndex;
    public WLAN_PROFILE_INFO[] ProfileInfo;

    public WLAN_PROFILE_INFO_LIST(IntPtr ppProfileList)
    {
        dwNumberOfItems = (uint)Marshal.ReadInt32(ppProfileList);
        dwIndex = (uint)Marshal.ReadInt32(ppProfileList, 4);
        ProfileInfo = new WLAN_PROFILE_INFO[dwNumberOfItems];
        IntPtr ppProfileListTemp = new IntPtr(ppProfileList.ToInt64() + 8);

        for (int i = 0; i < dwNumberOfItems; i++)
        {
            ppProfileList = new IntPtr(ppProfileListTemp.ToInt64() + i * Marshal.SizeOf(typeof(WLAN_PROFILE_INFO)));
            ProfileInfo[i] = (WLAN_PROFILE_INFO)Marshal.PtrToStructure(ppProfileList, typeof(WLAN_PROFILE_INFO));
        }
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_PROFILE_INFO
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public WlanProfileFlags ProfileFLags;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_AVAILABLE_NETWORK_LIST
{
    public uint dwNumberOfItems;
    public uint dwIndex;
    public WLAN_AVAILABLE_NETWORK[] wlanAvailableNetwork;
    public WLAN_AVAILABLE_NETWORK_LIST(IntPtr ppAvailableNetworkList)
    {
        dwNumberOfItems = (uint)Marshal.ReadInt64 (ppAvailableNetworkList);
        dwIndex = (uint)Marshal.ReadInt64 (ppAvailableNetworkList, 4);
        wlanAvailableNetwork = new WLAN_AVAILABLE_NETWORK[dwNumberOfItems];
        for (int i = 0; i < dwNumberOfItems; i++)
        {
            IntPtr pWlanAvailableNetwork = new IntPtr (ppAvailableNetworkList.ToInt64() + i * Marshal.SizeOf (typeof(WLAN_AVAILABLE_NETWORK)) + 8);
            wlanAvailableNetwork[i] = (WLAN_AVAILABLE_NETWORK)Marshal.PtrToStructure (pWlanAvailableNetwork, typeof(WLAN_AVAILABLE_NETWORK));
        }
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_AVAILABLE_NETWORK
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ProfileName;
    public DOT11_SSID Dot11Ssid;
    public DOT11_BSS_TYPE dot11BssType;
    public uint uNumberOfBssids;
    public bool bNetworkConnectable;
    public uint wlanNotConnectableReason;
    public uint uNumberOfPhyTypes;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public DOT11_PHY_TYPE[] dot11PhyTypes;
    public bool bMorePhyTypes;
    public uint SignalQuality;
    public bool SecurityEnabled;
    public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
    public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
    public uint dwFlags;
    public uint dwReserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct DOT11_SSID
{
    /// ULONG->unsigned int
    public uint uSSIDLength;

    /// UCHAR[]
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string ucSSID;
}

public enum DOT11_BSS_TYPE
{
    Infrastructure = 1,
    Independent    = 2,
    Any            = 3,
}

public enum DOT11_PHY_TYPE
{
    dot11_phy_type_unknown = 0,
    dot11_phy_type_any = 0,
    dot11_phy_type_fhss = 1,
    dot11_phy_type_dsss = 2,
    dot11_phy_type_irbaseband = 3,
    dot11_phy_type_ofdm = 4,
    dot11_phy_type_hrdsss = 5,
    dot11_phy_type_erp = 6,
    dot11_phy_type_ht = 7,
    dot11_phy_type_vht = 8,
    dot11_phy_type_IHV_start = -2147483648,
    dot11_phy_type_IHV_end = -1,
}

public enum DOT11_AUTH_ALGORITHM
{
    DOT11_AUTH_ALGO_80211_OPEN = 1,
    DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
    DOT11_AUTH_ALGO_WPA = 3,
    DOT11_AUTH_ALGO_WPA_PSK = 4,
    DOT11_AUTH_ALGO_WPA_NONE = 5,
    DOT11_AUTH_ALGO_RSNA = 6,
    DOT11_AUTH_ALGO_RSNA_PSK = 7,
    DOT11_AUTH_ALGO_WPA3  = 8,
    DOT11_AUTH_ALGO_WPA3_SAE  = 9,
    DOT11_AUTH_ALGO_OWE  = 10,
    DOT11_AUTH_ALGO_WPA3_ENT  = 11,
    DOT11_AUTH_ALGO_IHV_START = -2147483648,
    DOT11_AUTH_ALGO_IHV_END = -1,
}

public enum DOT11_CIPHER_ALGORITHM
{
    /// DOT11_CIPHER_ALGO_NONE -> 0x00
    DOT11_CIPHER_ALGO_NONE = 0,

    /// DOT11_CIPHER_ALGO_WEP40 -> 0x01
    DOT11_CIPHER_ALGO_WEP40 = 1,

    /// DOT11_CIPHER_ALGO_TKIP -> 0x02
    DOT11_CIPHER_ALGO_TKIP = 2,

    /// DOT11_CIPHER_ALGO_CCMP -> 0x04
    DOT11_CIPHER_ALGO_CCMP = 4,

    /// DOT11_CIPHER_ALGO_WEP104 -> 0x05
    DOT11_CIPHER_ALGO_WEP104 = 5,

    /// DOT11_CIPHER_ALGO_BIP -> 0x06
    DOT11_CIPHER_ALGO_BIP = 6,

    /// DOT11_CIPHER_ALGO_GCMP -> 0x08
    DOT11_CIPHER_ALGO_GCMP = 8,

    /// DOT11_CIPHER_ALGO_GCMP_256 -> 0x09
    DOT11_CIPHER_ALGO_GCMP_256 = 9,

    /// DOT11_CIPHER_ALGO_CCMP_256 -> 0x0a
    DOT11_CIPHER_ALGO_CCMP_256 = 10,

    /// DOT11_CIPHER_ALGO_BIP_GMAC_128 -> 0x0b
    DOT11_CIPHER_ALGO_BIP_GMAC_128 = 11,

    /// DOT11_CIPHER_ALGO_BIP_GMAC_256 -> 0x0c
    DOT11_CIPHER_ALGO_BIP_GMAC_256 = 12,

    /// DOT11_CIPHER_ALGO_BIP_CMAC_256 -> 0x0d
    DOT11_CIPHER_ALGO_BIP_CMAC_256 = 13,

    /// DOT11_CIPHER_ALGO_WPA_USE_GROUP -> 0x100
    DOT11_CIPHER_ALGO_WPA_USE_GROUP = 256,

    /// DOT11_CIPHER_ALGO_RSN_USE_GROUP -> 0x100
    DOT11_CIPHER_ALGO_RSN_USE_GROUP = 256,

    /// DOT11_CIPHER_ALGO_WEP -> 0x101
    DOT11_CIPHER_ALGO_WEP = 257,

    /// DOT11_CIPHER_ALGO_IHV_START -> 0x80000000
    DOT11_CIPHER_ALGO_IHV_START = -2147483648,

    /// DOT11_CIPHER_ALGO_IHV_END -> 0xffffffff
    DOT11_CIPHER_ALGO_IHV_END = -1,
}

public enum WLAN_CONNECTION_MODE
{
    wlan_connection_mode_profile,
    wlan_connection_mode_temporary_profile,
    wlan_connection_mode_discovery_secure,
    wlan_connection_mode_discovery_unsecure,
    wlan_connection_mode_auto,
    wlan_connection_mode_invalid,
}

[Flags]
public enum WlanConnectionFlag
{
    Default                                    = 0,
    HiddenNetwork                              = 1,
    AdhocJoinOnly                              = 2,
    IgnorePrivayBit                            = 4,
    EapolPassThrough                           = 8,
    PersistDiscoveryProfile                    = 10,
    PersistDiscoveryProfileConnectionModeAuto  = 20,
    PersistDiscoveryProfileOverwriteExisting   = 40
}

[Flags]
public enum WlanProfileFlags
{
    AllUser = 0,
    GroupPolicy = 1,
    User = 2
}

public class ProfileInfo
{
    public string ProfileName;
    public string ConnectionMode;
    public string Authentication;
    public string Encryption;
    public string Password;
    public bool ConnectHiddenSSID;
    public string EAPType;
    public string ServerNames;
    public string TrustedRootCA;
    public string Xml;
}

[DllImport("Wlanapi.dll", SetLastError = true)]
public static extern uint WlanEnumInterfaces (
    [In] IntPtr hClientHandle,
    [In] IntPtr pReserved,
    [Out] out IntPtr ppInterfaceList
);

public struct WLAN_INTERFACE_INFO_LIST
{
    public uint dwNumberOfItems;
    public uint dwIndex;
    public WLAN_INTERFACE_INFO[] wlanInterfaceInfo;
    public WLAN_INTERFACE_INFO_LIST(IntPtr ppInterfaceInfoList)
    {
        dwNumberOfItems = (uint)Marshal.ReadInt32(ppInterfaceInfoList);
        dwIndex = (uint)Marshal.ReadInt32(ppInterfaceInfoList, 4);
        wlanInterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberOfItems];
        IntPtr ppInterfaceInfoListTemp = new IntPtr(ppInterfaceInfoList.ToInt64() + 8);
        for (int i = 0; i < dwNumberOfItems; i++)
        {
            ppInterfaceInfoList = new IntPtr(ppInterfaceInfoListTemp.ToInt64() + i * Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO)));
            wlanInterfaceInfo[i] = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(ppInterfaceInfoList, typeof(WLAN_INTERFACE_INFO));
        }
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_INTERFACE_INFO
{
    public Guid Guid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;
    public WLAN_INTERFACE_STATE State;
}

public enum WLAN_INTERFACE_STATE {
    not_ready              = 0,
    connected              = 1,
    ad_hoc_network_formed  = 2,
    disconnecting          = 3,
    disconnected           = 4,
    associating            = 5,
    discovering            = 6,
    authenticating         = 7
}

[DllImport("Wlanapi.dll",SetLastError=true)]
public static extern uint WlanScan(
    IntPtr hClientHandle,
    ref Guid pInterfaceGuid,
    IntPtr pDot11Ssid,
    IntPtr pIeData,
    IntPtr pReserved
);

[DllImport("Wlanapi.dll")]
public static extern uint WlanSetInterface(
    IntPtr hClientHandle,
    ref Guid pInterfaceGuid,
    WLAN_INTF_OPCODE OpCode,
    uint dwDataSize,
    IntPtr pData ,
    IntPtr pReserved
);

public enum WLAN_INTF_OPCODE
{
    /// wlan_intf_opcode_autoconf_start -> 0x000000000
    wlan_intf_opcode_autoconf_start = 0,

    wlan_intf_opcode_autoconf_enabled,

    wlan_intf_opcode_background_scan_enabled,

    wlan_intf_opcode_media_streaming_mode,

    wlan_intf_opcode_radio_state,

    wlan_intf_opcode_bss_type,

    wlan_intf_opcode_interface_state,

    wlan_intf_opcode_current_connection,

    wlan_intf_opcode_channel_number,

    wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,

    wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,

    wlan_intf_opcode_supported_country_or_region_string_list,

    wlan_intf_opcode_current_operation_mode,

    wlan_intf_opcode_supported_safe_mode,

    wlan_intf_opcode_certified_safe_mode,

    /// wlan_intf_opcode_autoconf_end -> 0x0fffffff
    wlan_intf_opcode_autoconf_end = 268435455,

    /// wlan_intf_opcode_msm_start -> 0x10000100
    wlan_intf_opcode_msm_start = 268435712,

    wlan_intf_opcode_statistics,

    wlan_intf_opcode_rssi,

    /// wlan_intf_opcode_msm_end -> 0x1fffffff
    wlan_intf_opcode_msm_end = 536870911,

    /// wlan_intf_opcode_security_start -> 0x20010000
    wlan_intf_opcode_security_start = 536936448,

    /// wlan_intf_opcode_security_end -> 0x2fffffff
    wlan_intf_opcode_security_end = 805306367,

    /// wlan_intf_opcode_ihv_start -> 0x30000000
    wlan_intf_opcode_ihv_start = 805306368,

    /// wlan_intf_opcode_ihv_end -> 0x3fffffff
    wlan_intf_opcode_ihv_end = 1073741823,
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WlanPhyRadioState
{
    public int dwPhyIndex;
    public Dot11RadioState dot11SoftwareRadioState;
    public Dot11RadioState dot11HardwareRadioState;
}

public enum Dot11RadioState : uint
{
    Unknown = 0,
    On,
    Off
}

public enum WLAN_OPCODE_VALUE_TYPE
{
    /// wlan_opcode_value_type_query_only -> 0
    wlan_opcode_value_type_query_only = 0,

    /// wlan_opcode_value_type_set_by_group_policy -> 1
    wlan_opcode_value_type_set_by_group_policy = 1,

    /// wlan_opcode_value_type_set_by_user -> 2
    wlan_opcode_value_type_set_by_user = 2,

    /// wlan_opcode_value_type_invalid -> 3
    wlan_opcode_value_type_invalid = 3
}

[DllImport("Wlanapi", EntryPoint = "WlanQueryInterface")]
public static extern uint WlanQueryInterface(
    [In] IntPtr hClientHandle,
    [In] ref Guid pInterfaceGuid,
    WLAN_INTF_OPCODE OpCode,
    IntPtr pReserved,
    [Out] out uint pdwDataSize,
    ref IntPtr ppData,
    IntPtr pWlanOpcodeValueType
);

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_CONNECTION_ATTRIBUTES
{
    /// WLAN_INTERFACE_STATE->_WLAN_INTERFACE_STATE
    public WLAN_INTERFACE_STATE isState;

    /// WLAN_CONNECTION_MODE->_WLAN_CONNECTION_MODE
    public WLAN_CONNECTION_MODE wlanConnectionMode;

    /// WCHAR[256]
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;

    /// WLAN_ASSOCIATION_ATTRIBUTES->_WLAN_ASSOCIATION_ATTRIBUTES
    public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;

    /// WLAN_SECURITY_ATTRIBUTES->_WLAN_SECURITY_ATTRIBUTES
    public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DOT11_MAC_ADDRESS
{
     public byte one;
     public byte two;
     public byte three;
     public byte four;
     public byte five;
     public byte six;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_ASSOCIATION_ATTRIBUTES
{
    /// DOT11_SSID->_DOT11_SSID
    public DOT11_SSID dot11Ssid;

    /// DOT11_BSS_TYPE->_DOT11_BSS_TYPE
    public DOT11_BSS_TYPE dot11BssType;

    /// DOT11_MAC_ADDRESS->UCHAR[6]
    //// public DOT11_MAC_ADDRESS dot11Bssid;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] _dot11Bssid;

    /// DOT11_PHY_TYPE->_DOT11_PHY_TYPE
    public DOT11_PHY_TYPE dot11PhyType;

    /// ULONG->unsigned int
    public uint uDot11PhyIndex;

    /// WLAN_SIGNAL_QUALITY->ULONG->unsigned int
    public uint wlanSignalQuality;

    /// ULONG->unsigned int
    public uint ulRxRate;

    /// ULONG->unsigned int
    public uint ulTxRate;
}

[StructLayout(LayoutKind.Sequential)]
public struct WLAN_SECURITY_ATTRIBUTES
{
    /// <summary>
    /// BOOL->int
    /// </summary>
    [MarshalAs(UnmanagedType.Bool)]
    public bool bSecurityEnabled;

    /// <summary>
    /// BOOL->int
    /// </summary>
    [MarshalAs(UnmanagedType.Bool)]
    public bool bOneXEnabled;

    /// <summary>
    /// DOT11_AUTH_ALGORITHM->_DOT11_AUTH_ALGORITHM
    /// </summary>
    public DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;

    /// <summary>
    /// DOT11_CIPHER_ALGORITHM->_DOT11_CIPHER_ALGORITHM
    /// </summary>
    public DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
}
'@

Add-Type -MemberDefinition $WlanGetProfileListSig -Name ProfileManagement -Namespace WiFi -Using System.Text -PassThru | Out-Null

function Add-DefaultProperty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [object]
        $InputObject,

        [Parameter(Mandatory)]
        [object]
        $InterfaceInfo
    )

    Add-Member -InputObject $InputObject -MemberType 'NoteProperty' -Name 'WiFiAdapterName' -Value $InterfaceInfo.Name -Force
    Add-Member -InputObject $InputObject -MemberType 'NoteProperty' -Name 'InterfaceGuid' -Value $InterfaceInfo.InterfaceGuid -Force

    if ($InputObject -is  [WiFi.ProfileManagement+WLAN_CONNECTION_ATTRIBUTES])
    {
        $apMac = [System.BitConverter]::ToString($InputObject.wlanAssociationAttributes._dot11Bssid)
        Add-Member -InputObject $InputObject -MemberType 'NoteProperty' -Name 'APMacAddress' -Value $apMac -Force
    }

    return $InputObject
}


function Format-WiFiReasonCode
{
    [OutputType([System.String])]
    [Cmdletbinding()]
    param
    (
        [Parameter()]
        [System.IntPtr]
        $ReasonCode
    )

    $stringBuilder = New-Object -TypeName Text.StringBuilder
    $stringBuilder.Capacity = 1024

    $result = [WiFi.ProfileManagement]::WlanReasonCodeToString(
        $ReasonCode.ToInt32(),
        $stringBuilder.Capacity,
        $stringBuilder,
        [IntPtr]::zero
    )

    if ($result -ne 0)
    {
        $errorMessage = Format-Win32Exception -ReturnCode $result
        Write-Error -Message ($script:localizedData.ErrorReasonCode -f $errorMessage)
    }

    return $stringBuilder.ToString()
}


function Format-Win32Exception
{
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $ReturnCode
    )

    return [System.ComponentModel.Win32Exception]::new($ReturnCode).Message
}


function Get-InterfaceInfo
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName
    )

    $result = @()
    $wifiAdapters = @()
    $getNetAdapterParams = @()

    $wifiInterfaces = Get-WiFiInterface

    if (!$WiFiAdapterName)
    {
        foreach ($wifiInterface in $wifiInterfaces)
        {
            $getNetAdapterParams +=@(
                 @{InterfaceDescription = $wifiInterface.Description}
            )
        }
    }
    else
    {
        $getNetAdapterParams = @(
            @{Name = $WiFiAdapterName}
        )
    }

    foreach ($getNetAdapterParam in $getNetAdapterParams)
    {
        $wifiAdapters = Get-NetAdapter @getNetAdapterParam
    }

    
    foreach ($wifiAdapter in $wifiAdapters)
    {
        if ($wifiAdapter.InterfaceGuid -notin $wifiInterfaces.Guid)
        {
            Write-Error -Message ($script:localizedData.ErrorNotWiFiAdapter -f $wifiAdapter.Name)
        }
        else
        {
            $result += $wifiAdapter
        }
    }

    if ($result.Count -eq 0)
    {
        throw $script:localizedData.ErrorNoWiFiAdaptersFound
    }
    return $result
}


function Get-WiFiInterface
{
    [CmdletBinding()]
    [OutputType([WiFi.ProfileManagement+WLAN_INTERFACE_INFO])]
    param ()

    $interfaceListPtr = 0
    $clientHandle = New-WiFiHandle

    try
    {
        [void] [WiFi.ProfileManagement]::WlanEnumInterfaces($clientHandle, [IntPtr]::zero, [ref] $interfaceListPtr)
        $wiFiInterfaceList = [WiFi.ProfileManagement+WLAN_INTERFACE_INFO_LIST]::new($interfaceListPtr)

        foreach ($wlanInterfaceInfo in $wiFiInterfaceList.wlanInterfaceInfo)
        {
            [WiFi.ProfileManagement+WLAN_INTERFACE_INFO] $wlanInterfaceInfo
        }
    }
    catch
    {
        Write-Error $PSItem
    }
    finally
    {
        Remove-WiFiHandle -ClientHandle $clientHandle
    }
}


function Get-WiFiProfileInfo
{
    [OutputType([System.Management.Automation.PSCustomObject])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $ProfileName,

        [Parameter()]
        [System.Guid]
        $InterfaceGuid,

        [Parameter()]
        [System.IntPtr]
        $ClientHandle,

        [System.Int16]
        $WlanProfileFlags
    )
    
    begin
    {
        [String] $pstrProfileXml = $null
        $wlanAccess = 0
        $WlanProfileFlagsInput = $WlanProfileFlags
    }
    process
    {
        $result = [WiFi.ProfileManagement]::WlanGetProfile(
            $ClientHandle,
            $InterfaceGuid,
            $ProfileName,
            [IntPtr]::Zero,
            [ref] $pstrProfileXml,
            [ref] $WlanProfileFlags,
            [ref] $wlanAccess
        )

        if ($result -ne 0)
        {
            $errorMessage = Format-Win32Exception -ReturnCode $result
            throw $($script:localizedData.ErrorGettingProfile -f $errorMessage)
        }

        $wlanProfile = [xml] $pstrProfileXml

        
        if ($WlanProfileFlagsInput -eq 13)
        {
            $password = $wlanProfile.WLANProfile.MSM.security.sharedKey.keyMaterial
        }
        else
        {
            $password = $null
        }

        
        if ([bool]::TryParse($wlanProfile.WLANProfile.SSIDConfig.nonBroadcast, [ref] $null))
        {
            $connectHiddenSSID = [bool]::Parse($wlanProfile.WLANProfile.SSIDConfig.nonBroadcast)
        }
        else
        {
            $connectHiddenSSID = $false
        }

        
        if ($wlanProfile.WLANProfile.MSM.security.authEncryption.useOneX -eq 'true')
        {
            switch ($wlanProfile.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.EapMethod.Type.InnerText)
            {
                '25'    
                {
                    $eapType = 'PEAP'
                }

                '13'    
                {
                    $eapType = 'TLS'
                }

                Default
                {
                    $eapType = 'Unknown'
                }
            }
        }
        else
        {
            $eapType = $null
        }

        
        if ($null -ne $eapType)
        {
            switch ($eapType)
            {
                'PEAP'
                { 
                    $serverNames = $wlanProfile.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.ServerNames
                }

                'TLS'
                {
                    $node = $wlanProfile.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.SelectNodes("//*[local-name()='ServerNames']")
                    $serverNames = $node[0].InnerText
                }
            }
        }

        
        if ($null -ne $eapType)
        {
            switch ($eapType)
            {
                'PEAP'
                { 
                    $trustedRootCa = ([string] ($wlanProfile.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.TrustedRootCA -replace ' ', [string]::Empty)).ToLower()
                }

                'TLS'
                {
                    $node = $wlanProfile.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.SelectNodes("//*[local-name()='TrustedRootCA']")
                    $trustedRootCa = ([string] ($node[0].InnerText -replace ' ', [string]::Empty)).ToLower()
                }
            }
        }


        [WiFi.ProfileManagement+ProfileInfo]@{
            ProfileName       = $wlanProfile.WLANProfile.SSIDConfig.SSID.name
            ConnectionMode    = $wlanProfile.WLANProfile.connectionMode
            Authentication    = $wlanProfile.WLANProfile.MSM.security.authEncryption.authentication
            Encryption        = $wlanProfile.WLANProfile.MSM.security.authEncryption.encryption
            Password          = $password
            ConnectHiddenSSID = $connectHiddenSSID
            EAPType           = $eapType
            ServerNames       = $serverNames
            TrustedRootCA     = $trustedRootCa
            Xml               = $pstrProfileXml
        }
    }
    end
    {
        $xmlPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAuto($pstrProfileXml)
        Invoke-WlanFreeMemory -Pointer $xmlPtr
    }
}


function Invoke-WlanConnect
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.IntPtr]
        $ClientHandle,

        [Parameter(Mandatory = $true)]
        [System.Guid]
        $InterfaceGuid,

        [Parameter(Mandatory = $true)]
        [WiFi.ProfileManagement+WLAN_CONNECTION_PARAMETERS]
        $ConnectionParameterList
    )

    $result = [WiFi.ProfileManagement]::WlanConnect(
        $ClientHandle,
        [ref] $InterfaceGuid,
        [ref] $ConnectionParameterList,
        [IntPtr]::Zero
    )

    if ($result -ne 0)
    {
        $errorMessage = Format-Win32Exception -ReturnCode $result
        throw $($script:localizedData.ErrorWlanConnect -f $ConnectionParameterList.strProfile, $errorMessage)
    }
    else
    {
        Write-Verbose -Message $($script:localizedData.SuccessWlanConnect -f $ConnectionParameterList.strProfile, $errorMessage)
    }
}


function Invoke-WlanFreeMemory
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.IntPtr[]]
        $Pointer
    )

    foreach ($ptr in $Pointer)
    {
        if ($ptr -ne 0)
        {
            try
            {
                [WiFi.ProfileManagement]::WlanFreeMemory($ptr)
            }
            catch
            {
                throw $($script:localizedData.ErrorFreeMemory -f $errorMessage)
            }
        }
    }
}


function New-WiFiConnectionParameter
{
    [OutputType([WiFi.ProfileManagement+WLAN_CONNECTION_PARAMETERS])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ProfileName,

        [Parameter()]
        [ValidateSet('Profile', 'TemporaryProfile', 'DiscoverySecure', 'DiscoveryUnsecure', 'Auto')]
        [System.String]
        $ConnectionMode = 'Profile',

        [Parameter()]
        [ValidateSet('Any', 'Independent', 'Infrastructure')]
        [WiFi.ProfileManagement+DOT11_BSS_TYPE]
        $Dot11BssType = 'Any',

        [Parameter()]
        [WiFi.ProfileManagement+WlanConnectionFlag]
        $Flag = 'Default'
    )

    try
    {
        
        $connectionModeResolver = @{
            Profile           = 'wlan_connection_mode_profile'
            TemporaryProfile  = 'wlan_connection_mode_temporary_profile'
            DiscoverySecure   = 'wlan_connection_mode_discovery_secure'
            DiscoveryUnsecure = 'wlan_connection_mode_discovery_unsecure'
            Auto              = 'wlan_connection_mode_auto'
        }
        

        $connectionParameters = [WiFi.ProfileManagement+WLAN_CONNECTION_PARAMETERS]::new()
        $connectionParameters.strProfile = $ProfileName
        $connectionParameters.wlanConnectionMode = [WiFi.ProfileManagement+WLAN_CONNECTION_MODE]::$($connectionModeResolver[$ConnectionMode])
        $connectionParameters.dot11BssType = [WiFi.ProfileManagement+DOT11_BSS_TYPE]::$Dot11BssType
        $connectionParameters.dwFlags = [WiFi.ProfileManagement+WlanConnectionFlag]::$Flag
    }
    catch
    {
        throw $PSItem
    }

    return $connectionParameters
}


function New-WiFiHandle
{    
    [CmdletBinding()]
    [OutputType([System.IntPtr])]
    param()

    $maxClient = 2
    [Ref]$negotiatedVersion = 0
    $clientHandle = [IntPtr]::zero

    $result = [WiFi.ProfileManagement]::WlanOpenHandle(
        $maxClient,
        [IntPtr]::Zero,
        $negotiatedVersion,
        [ref] $clientHandle
    )
    
    if ($result -eq 0)
    {
        return $clientHandle
    }
    else
    {
        $errorMessage = Format-Win32Exception -ReturnCode $result
        throw $($script:localizedData.ErrorOpeningHandle -f $errorMessage)
    }
}

$script:WiFiProfileXmlPersonal = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{0}</name>
  <SSIDConfig>
    <SSID>
      <name>{0}</name>
    </SSID>
    <nonBroadcast>{1}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>{2}</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{3}</authentication>
        <encryption>{4}</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{5}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"@

$script:WiFiProfileXmlEapPeap = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{0}</name>
  <SSIDConfig>
    <SSID>
      <name>{0}</name>
    </SSID>
    <nonBroadcast>{1}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>{2}</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{3}</authentication>
        <encryption>{4}</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <PMKCacheMode>enabled</PMKCacheMode>
      <PMKCacheTTL>720</PMKCacheTTL>
      <PMKCacheSize>128</PMKCacheSize>
      <preAuthMode>disabled</preAuthMode>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>machineOrUser</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
              <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                <Type>25</Type>
                <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
                  <ServerValidation>
                    <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
                    <ServerNames></ServerNames>
                    <TrustedRootCA></TrustedRootCA>
                  </ServerValidation>
                  <FastReconnect>true</FastReconnect>
                  <InnerEapOptional>false</InnerEapOptional>
                  <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                    <Type>26</Type>
                    <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
                      <UseWinLogonCredentials>false</UseWinLogonCredentials>
                    </EapType>
                  </Eap>
                  <EnableQuarantineChecks>false</EnableQuarantineChecks>
                  <RequireCryptoBinding>false</RequireCryptoBinding>
                  <PeapExtensions>
                    <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>
                    <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName>
                    <PeapExtensionsV2 xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">
                      <AllowPromptingWhenServerCANotFound xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3">true</AllowPromptingWhenServerCANotFound>
                    </PeapExtensionsV2>
                  </PeapExtensions>
                </EapType>
              </Eap>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"@

$script:WiFiProfileXmlEapTls = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{0}</name>
  <SSIDConfig>
    <SSID>
      <name>{0}</name>
    </SSID>
    <nonBroadcast>{1}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>{2}</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{3}</authentication>
        <encryption>{4}</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <PMKCacheMode>enabled</PMKCacheMode>
      <PMKCacheTTL>720</PMKCacheTTL>
      <PMKCacheSize>128</PMKCacheSize>
      <preAuthMode>disabled</preAuthMode>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>machineOrUser</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1" xmlns:eapTls="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
              <baseEap:Eap>
                <baseEap:Type>13</baseEap:Type>
                <eapTls:EapType>
                  <eapTls:CredentialsSource>
                    <eapTls:CertificateStore />
                  </eapTls:CredentialsSource>
                  <eapTls:ServerValidation>
                    <eapTls:DisableUserPromptForServerValidation>false</eapTls:DisableUserPromptForServerValidation>
                    <eapTls:ServerNames></eapTls:ServerNames>
                    <eapTls:TrustedRootCA></eapTls:TrustedRootCA>
                  </eapTls:ServerValidation>
                  <eapTls:DifferentUsername>false</eapTls:DifferentUsername>
                </eapTls:EapType>
              </baseEap:Eap>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"@



function New-WiFiProfileXml
{
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $ProfileName,

        [Parameter()]
        [ValidateSet('manual', 'auto')]
        [System.String]
        $ConnectionMode = 'auto',

        [Parameter()]
        [System.String]
        $Authentication = 'WPA2PSK',

        [Parameter()]
        [System.String]
        $Encryption = 'AES',

        [Parameter()]
        [System.Security.SecureString]
        $Password,

        [Parameter()]
        [System.Boolean]
        $ConnectHiddenSSID = $false,

        [Parameter()]
        [System.String]
        $EAPType,

        [Parameter()]
        [AllowEmptyString()]
        [System.String]
        $ServerNames = '',

        [Parameter()]
        [System.String]
        $TrustedRootCA
    )

    try
    {
        if ($Password)
        {
            $secureStringToBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($secureStringToBstr)
        }

        if ($EAPType -eq 'PEAP')
        {
            $profileXml = [xml] ($script:WiFiProfileXmlEapPeap -f $ProfileName, ([string] $ConnectHiddenSSID).ToLower(), $ConnectionMode, $Authentication, $Encryption)

            if ($ServerNames)
            {
                $profileXml.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.ServerNames = $ServerNames
            }

            if ($TrustedRootCA)
            {
                [string]$formattedCaHash = $TrustedRootCA -replace '..', '$& '
                $profileXml.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.TrustedRootCA = $formattedCaHash
            }
        }
        elseif ($EAPType -eq 'TLS')
        {
            $profileXml = [xml] ($script:WiFiProfileXmlEapTls -f $ProfileName, ([string] $ConnectHiddenSSID).ToLower(), $ConnectionMode, $Authentication, $Encryption)

            if ($ServerNames)
            {
                $node = $profileXml.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.SelectNodes("//*[local-name()='ServerNames']")
                $node[0].InnerText = $ServerNames
            }

            if ($TrustedRootCA)
            {
                [string]$formattedCaHash = $TrustedRootCA -replace '..', '$& '
                $node = $profileXml.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.SelectNodes("//*[local-name()='TrustedRootCA']")
                $node[0].InnerText = $formattedCaHash
            }
        }
        else
        {
            $profileXml = [xml] ($script:WiFiProfileXmlPersonal -f $ProfileName, ([string] $ConnectHiddenSSID).ToLower(), $ConnectionMode, $Authentication, $Encryption, $plainPassword)
            if (-not $plainPassword)
            {
                $null = $profileXml.WLANProfile.MSM.security.RemoveChild($profileXml.WLANProfile.MSM.security.sharedKey)
            }

            if ($Authentication -eq 'WPA3SAE'){
              
              $nsmg = [System.Xml.XmlNamespaceManager]::new($profileXml.NameTable)
              $nsmg.AddNamespace('WLANProfile', $profileXml.DocumentElement.GetAttribute('xmlns'))
              $refNode = $profileXml.SelectSingleNode('//WLANProfile:authEncryption', $nsmg)
              $xmlnode = $profileXml.CreateElement('transitionMode', 'http://www.microsoft.com/networking/WLAN/profile/v4')
              $xmlnode.InnerText = 'true'
              $null = $refNode.AppendChild($xmlnode)
            }
        }

        $profileXml.OuterXml
    }
    catch
    {
        throw $PSItem
    }
}


function Remove-WiFiHandle
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.IntPtr]
        $ClientHandle
    )

    $result = [WiFi.ProfileManagement]::WlanCloseHandle($ClientHandle, [IntPtr]::zero)

    if ($result -eq 0)
    {
        Write-Verbose -Message ($script:localizedData.HandleClosed)
    }
    else
    {
        $errorMessage = Format-Win32Exception -ReturnCode $result
        throw $($script:localizedData.ErrorClosingHandle -f $errorMessage)
    }
}


function Connect-WiFiProfile
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ProfileName,

        [Parameter()]
        [ValidateSet('Profile', 'TemporaryProfile', 'DiscoverySecure', 'DiscoveryUnsecure', 'Auto')]
        [System.String]
        $ConnectionMode = 'Profile',

        [Parameter()]
        [ValidateSet('Any', 'Independent', 'Infrastructure')]
        [System.String]
        $Dot11BssType = 'Any',

        [Parameter()]
        [System.String]
        $WiFiAdapterName
    )

    begin
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        if ($interfaceInfo.Count -gt 1)
        {
            throw $Script:localizedData.ErrorMoreThanOneInterface
        }
    }
    process
    {
        try
        {
            $clientHandle = New-WiFiHandle
            $connectionParameterList = New-WiFiConnectionParameter -ProfileName $ProfileName -ConnectionMode $ConnectionMode -Dot11BssType $Dot11BssType
            Invoke-WlanConnect -ClientHandle $clientHandle -InterfaceGuid $interfaceInfo.InterfaceGuid -ConnectionParameterList $connectionParameterList
        }
        catch
        {
            Write-Error $PSItem
        }
        finally
        {
            if ($clientHandle)
            {
                Remove-WiFiHandle -ClientHandle $clientHandle
            }
        }
    }
}


function Get-WiFiAvailableNetwork
{
    [CmdletBinding()]
    [OutputType([WiFi.ProfileManagement+WLAN_AVAILABLE_NETWORK])]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName,

        [Parameter()]
        [switch]
        $InvokeScan
    )

    try
    {
        if ($InvokeScan.IsPresent)
        {
            Search-WiFiNetwork -WiFiAdapterName $WiFiAdapterName
            
            
            Start-Sleep -Seconds 4
        }

        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        $flag = 0
        $networkList = @()
        $pointerCollection = @()
        $clientHandle = New-WiFiHandle

        foreach ($interface in $interfaceInfo)
        {
            $networkPointer = 0
            $result = [WiFi.ProfileManagement]::WlanGetAvailableNetworkList(
                $clientHandle,
                $interface.InterfaceGuid,
                $flag,
                [IntPtr]::zero,
                [ref] $networkPointer
            )

            if ($result -ne 0)
            {
                $errorMessage = Format-Win32Exception -ReturnCode $result
                throw $($script:localizedData.ErrorGetAvailableNetworkList -f $errorMessage)
            }

            $availableNetworks = [WiFi.ProfileManagement+WLAN_AVAILABLE_NETWORK_LIST]::new($networkPointer)
            $pointerCollection += $networkPointer

            foreach ($network in $availableNetworks.wlanAvailableNetwork)
            {
                $networkResult = [WiFi.ProfileManagement+WLAN_AVAILABLE_NETWORK] $network
                $networkList += Add-DefaultProperty -InputObject $networkResult -InterfaceInfo $interface
            }
        }

        $networkList
    }
    catch
    {
        $PSItem
    }
    finally
    {
        Invoke-WlanFreeMemory -Pointer $pointerCollection

        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }
    }
}


function Get-WiFiConnectionAttributes
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName
    )

    try
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        $result = @()
        $outDataCollection = @()
        $clientHandle = New-WiFiHandle

        foreach ($interface in $interfaceInfo)
        {
            $outData = [System.IntPtr]::zero
            $dataSize = [System.Runtime.InteropServices.Marshal]::SizeOf($outData)

            $resultCode = [WiFi.ProfileManagement]::WlanQueryInterface(
                $clientHandle,
                [ref] $interface.InterfaceGuid,
                [WiFi.ProfileManagement+WLAN_INTF_OPCODE]::wlan_intf_opcode_current_connection,
                [IntPtr]::zero,
                [ref]$dataSize,
                [ref]$outData,
                [IntPtr]::zero
            )

            if ($resultCode -ne 0)
            {
                Write-Error -Message ($script:localizedData.ErrorFailedWithExitCode -f $resultCode)
            }

            $attributes = [System.Runtime.InteropServices.Marshal]::ptrToStructure(
                $outData,
                [System.Type]([WiFi.ProfileManagement+WLAN_CONNECTION_ATTRIBUTES])
            )

            $outDataCollection += $outData

            $result += Add-DefaultProperty -InputObject $attributes -InterfaceInfo $interface
        }

        $result
    }
    catch
    {
        $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }

        if ($outDataCollection)
        {
            Invoke-WlanFreeMemory -Pointer $outDataCollection
        }
    }
}


function Get-WiFiProfile
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param
    (
        [Parameter(Position = 0)]
        [System.String[]]
        $ProfileName,

        [Parameter()]
        [System.String]
        $WiFiAdapterName,

        [Parameter()]
        [Switch]
        $ClearKey
    )

    try
    {
        $result = @()
        $profileListPointer = 0
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName
        $clientHandle = New-WiFiHandle

        if ($ClearKey)
        {
            $wlanProfileFlags = 13
        }
        else
        {
            $wlanProfileFlags = 0
        }

        if (!$ProfileName)
        {
            foreach ($interface in $interfaceInfo)
            {
                [void] [WiFi.ProfileManagement]::WlanGetProfileList(
                    $clientHandle,
                    $interface.InterfaceGuid,
                    [IntPtr]::zero,
                    [ref] $profileListPointer
                )

                $wiFiProfileList = [WiFi.ProfileManagement+WLAN_PROFILE_INFO_LIST]::new($profileListPointer)
                $ProfileName = ($wiFiProfileList.ProfileInfo).strProfileName
            }
        }

        foreach ($wiFiProfile in $ProfileName)
        {
            foreach ($interface in $interfaceInfo)
            {
                $profileInfo = Get-WiFiProfileInfo -ProfileName $wiFiProfile -InterfaceGuid $interface.InterfaceGuid -ClientHandle $clientHandle -WlanProfileFlags $wlanProfileFlags
                $result += Add-DefaultProperty -InputObject $profileInfo -InterfaceInfo $interface
            }
        }

        $result
    }
    catch
    {
        Write-Error $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }
    }
}


function Get-WiFiRssi
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName
    )

    try
    {
        $result = @()
        $pointerCollection = @()
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName
        $clientHandle = New-WiFiHandle

        $outData = [System.IntPtr]::zero
        [int]$dataSize = 0
        [WiFi.ProfileManagement+WLAN_OPCODE_VALUE_TYPE]$opcodeValueType = 0

        foreach ($interface in $interfaceInfo)
        {
            $resultCode = [WiFi.ProfileManagement]::WlanQueryInterface(
                $clientHandle,
                [ref] $interface.InterfaceGuid,
                [WiFi.ProfileManagement+WLAN_INTF_OPCODE]::wlan_intf_opcode_rssi,
                [IntPtr]::zero,
                [ref]$dataSize,
                [ref]$outData,
                $opcodeValueType 
            )

            if ($resultCode -ne 0)
            {
                return $resultCode
            }

            $pointerCollection += $outData
            $rssi = [PSCustomObject]@{
                Rssi = [System.Runtime.InteropServices.Marshal]::ReadInt32($outData)
            }

            $result += Add-DefaultProperty -InputObject $rssi -InterfaceInfo $interface
        }

        $result
    }
    catch
    {
        $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }

        if ($outData)
        {
            Invoke-WlanFreeMemory -Pointer $pointerCollection
        }
    }
}


function New-WiFiProfile
{
    [CmdletBinding(DefaultParameterSetName = 'UsingArguments')]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'UsingArguments')]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'UsingArgumentsWithEAP')]
        [Alias('SSID', 'Name')]
        [System.String]
        $ProfileName,

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('manual', 'auto')]
        [System.String]
        $ConnectionMode = 'auto',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('open', 'shared', 'WPA', 'WPAPSK', 'WPA2', 'WPA2PSK', 'WPA3SAE', 'WPA3ENT192', 'OWE')]
        [System.String]
        $Authentication = 'WPA2PSK',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('none', 'WEP', 'TKIP', 'AES', 'GCMP256')]
        [System.String]
        $Encryption = 'AES',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [System.Security.SecureString]
        $Password,

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [System.Boolean]
        $ConnectHiddenSSID = $false,

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('PEAP', 'TLS')]
        [System.String]
        $EAPType,

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [AllowEmptyString()]
        [System.String]
        $ServerNames = '',

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [System.String]
        $TrustedRootCA,

        [Parameter()]
        [System.String]
        $WiFiAdapterName,

        [Parameter(Mandatory = $true, ParameterSetName = 'UsingXml')]
        [System.String]
        $XmlProfile,

        [Parameter(DontShow = $true)]
        [System.Boolean]
        $Overwrite = $false
    )

    try
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        if ($interfaceInfo.Count -gt 1)
        {
            throw $Script:localizedData.ErrorNeedSingleAdapterName
        }

        $clientHandle = New-WiFiHandle
        $flags = 0
        $reasonCode = [IntPtr]::Zero

        if ($XmlProfile)
        {
            $profileXML = $XmlProfile
        }
        else
        {
            $newProfileParameters = @{
                ProfileName       = $ProfileName
                ConnectionMode    = $ConnectionMode
                Authentication    = $Authentication
                Encryption        = $Encryption
                Password          = $Password
                ConnectHiddenSSID = $ConnectHiddenSSID
                EAPType           = $EAPType
                ServerNames       = $ServerNames
                TrustedRootCA     = $TrustedRootCA
            }

            $profileXML = New-WiFiProfileXml @newProfileParameters
        }

        $profilePointer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($profileXML)

        $returnCode = [WiFi.ProfileManagement]::WlanSetProfile(
            $clientHandle,
            [ref] $interfaceInfo.InterfaceGuid,
            $flags,
            $profilePointer,
            [IntPtr]::Zero,
            $Overwrite,
            [IntPtr]::Zero,
            [ref]$reasonCode
        )

        $returnCodeMessage = Format-Win32Exception -ReturnCode $returnCode
        $reasonCodeMessage = Format-WiFiReasonCode -ReasonCode $reasonCode

        if ($returnCode -eq 0)
        {
            Write-Verbose -Message $returnCodeMessage
        }
        else
        {
            throw $returnCodeMessage
        }

        Write-Verbose -Message $reasonCodeMessage
    }
    catch
    {
        $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }
    }
}


function Remove-WiFiProfile
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        $ProfileName,

        [Parameter(Position = 1)]
        [System.String]
        $WiFiAdapterName
    )

    begin
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName
    }
    process
    {
        try
        {
            $clientHandle = New-WiFiHandle

            foreach ($wiFiProfile in $ProfileName)
            {
                foreach ($interface in $interfaceInfo)
                {
                    if ($PSCmdlet.ShouldProcess("$($script:localizedData.ShouldProcessDelete -f $WiFiProfile)"))
                    {
                        $deleteProfileResult = [WiFi.ProfileManagement]::WlanDeleteProfile(
                            $clientHandle,
                            $interface.InterfaceGuid,
                            $wiFiProfile,
                            [IntPtr]::Zero
                        )

                        $deleteProfileResultMessage = Format-Win32Exception -ReturnCode $deleteProfileResult

                        if ($deleteProfileResult -ne 0)
                        {
                            Write-Error -Message ($script:localizedData.ErrorDeletingProfile -f $deleteProfileResultMessage)
                        }
                        else
                        {
                            Write-Verbose -Message $deleteProfileResultMessage
                        }
                    }
                }
            }
        }
        catch
        {
            Write-Error $PSItem
        }
        finally
        {
            if ($clientHandle)
            {
                Remove-WiFiHandle -ClientHandle $clientHandle
            }
        }
    }
}


function Search-WiFiNetwork
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName
    )

    try
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        $clientHandle = New-WiFiHandle

        foreach ($interface in $interfaceInfo)
        {
            $resultCode = [WiFi.ProfileManagement]::WlanScan(
                $clientHandle,
                [ref] $interface.InterfaceGuid,
                [IntPtr]::zero,
                [IntPtr]::zero,
                [IntPtr]::zero
            )

            if ($resultCode -ne 0)
            {
                $resultCode
            }
        }
    }
    catch
    {
        $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            Remove-WiFiHandle -ClientHandle $clientHandle
        }
    }
}


function Set-WiFiProfile
{
    [CmdletBinding(DefaultParameterSetName = 'UsingArguments')]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'UsingArguments')]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'UsingArgumentsWithEAP')]
        [Alias('SSID', 'Name')]
        [System.String]
        $ProfileName,

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('manual', 'auto')]
        [System.String]
        $ConnectionMode = 'auto',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('open', 'shared', 'WPA', 'WPAPSK', 'WPA2', 'WPA2PSK', 'WPA3SAE', 'WPA3ENT192', 'OWE')]
        [System.String]
        $Authentication = 'WPA2PSK',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('none', 'WEP', 'TKIP', 'AES', 'GCMP256')]
        [System.String]
        $Encryption = 'AES',

        [Parameter(ParameterSetName = 'UsingArguments')]
        [System.Security.SecureString]
        $Password,

        [Parameter(ParameterSetName = 'UsingArguments')]
        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [System.Boolean]
        $ConnectHiddenSSID = $false,

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [ValidateSet('PEAP', 'TLS')]
        [System.String]
        $EAPType,

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [AllowEmptyString()]
        [System.String]
        $ServerNames = '',

        [Parameter(ParameterSetName = 'UsingArgumentsWithEAP')]
        [System.String]
        $TrustedRootCA,

        [Parameter()]
        [System.String]
        $WiFiAdapterName,

        [Parameter(Mandatory = $true, ParameterSetName = 'UsingXml')]
        [System.String]
        $XmlProfile
    )

    New-WiFiProfile @PSBoundParameters -Overwrite $true
}


function Set-WiFiInterface
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $WiFiAdapterName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('On','Off')]
        [string]
        $State
    )

    try
    {
        $interfaceInfo = Get-InterfaceInfo -WiFiAdapterName $WiFiAdapterName

        $clientHandle = New-WiFiHandle

        $radioStatePtr = [System.IntPtr]::new(0L)
        $radioState = [WiFi.ProfileManagement+WlanPhyRadioState]::new()
        $radioState.dot11SoftwareRadioState = [WiFi.ProfileManagement+Dot11RadioState]::$State
        $radioState.dot11HardwareRadioState = [WiFi.ProfileManagement+Dot11RadioState]::$State
        $opCode = [WiFi.ProfileManagement+WLAN_INTF_OPCODE]::wlan_intf_opcode_radio_state
        $radioStateSize = [System.Runtime.InteropServices.Marshal]::SizeOf($radioState)
        $radioStatePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($radioStateSize)

        [System.Runtime.InteropServices.Marshal]::StructureToPtr($radioState, $radioStatePtr, $false)

        foreach ($interface in $interfaceInfo)
        {
            $resultCode = [WiFi.ProfileManagement]::WlanSetInterface(
                $clientHandle,
                [ref] $interface.InterfaceGuid,
                $opCode,
                [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type]([WiFi.ProfileManagement+WlanPhyRadioState])),
                $radioStatePtr,
                [IntPtr]::zero
            )

            if ($resultCode -ne 0)
            {
                $resultCode
            }
        }
    }
    catch
    {
        Write-Error -Exception $PSItem
    }
    finally
    {
        if ($clientHandle)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($radioStatePtr)
            Remove-WiFiHandle -ClientHandle $clientHandle
        }
    }
}
