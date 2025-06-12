# Impacket Wiki - Not up to date needs work

## 📚 Documentation Status
- **Total Tools Documented**: 60+
- **Detailed Documentation**: 10 (Fully detailed)
- **Template Documentation**: 50+ (Template with customization needed)
- **Special Guides**: 3

## 🎯 Core Documentation (Fully Detailed)

### Authentication & Credential Attacks
- ✅ [addcomputer.py](addcomputer.md) - Add computer accounts to domain
- ✅ [GetNPUsers.py](GetNPUsers.md) - ASREPRoast attack  
- ✅ [GetUserSPNs.py](GetUserSPNs.md) - Kerberoasting attack
- ✅ [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks
- ✅ [secretsdump.py](secretsdump.md) - Extract credentials from Windows systems

### Remote Command Execution
- ✅ [psexec.py](psexec.md) - PsExec-like remote execution
- ✅ [wmiexec.py](wmiexec.md) - WMI-based remote execution

### Network Services
- ✅ [smbclient.py](smbclient.md) - SMB client functionality

### Privilege Escalation
- ✅ [rbcd.py](rbcd.md) - Resource-based constrained delegation

### Special Guides
- ✅ [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Essential commands and syntax
- ✅ [ATTACK_METHODOLOGIES.md](ATTACK_METHODOLOGIES.md) - Complete attack chains

## 📋 Template Documentation (Needs Customization)

### Authentication Tools
- 📝 [changepasswd.py](changepasswd.md)
- 📝 [getST.py](getST.md)  
- 📝 [getTGT.py](getTGT.md)
- 📝 [goldenPac.py](goldenPac.md)
- 📝 [keylistattack.py](keylistattack.md)
- 📝 [ticketer.py](ticketer.md)
- 📝 [ticketConverter.py](ticketConverter.md)

### Credential Extraction
- 📝 [DumpNTLMInfo.py](DumpNTLMInfo.md)
- 📝 [mimikatz.py](mimikatz.md)
- 📝 [dpapi.py](dpapi.md)
- 📝 [regsecrets.py](regsecrets.md)

### Remote Execution
- 📝 [smbexec.py](smbexec.md)
- 📝 [dcomexec.py](dcomexec.md)
- 📝 [atexec.py](atexec.md)

### Active Directory Enumeration  
- 📝 [GetADUsers.py](GetADUsers.md)
- 📝 [GetADComputers.py](GetADComputers.md)
- 📝 [findDelegation.py](findDelegation.md)
- 📝 [GetLAPSPassword.py](GetLAPSPassword.md)
- 📝 [Get-GPPPassword.py](Get-GPPPassword.md)

### Privilege Escalation & Persistence
- 📝 [dacledit.py](dacledit.md)
- 📝 [owneredit.py](owneredit.md)
- 📝 [raiseChild.py](raiseChild.md)
- 📝 [wmipersist.py](wmipersist.md)

### Network Services & Protocols
- 📝 [smbserver.py](smbserver.md)
- 📝 [mssqlclient.py](mssqlclient.md)
- 📝 [mssqlinstance.py](mssqlinstance.md)
- 📝 [rpcdump.py](rpcdump.md)
- 📝 [rpcmap.py](rpcmap.md)
- 📝 [sambaPipe.py](sambaPipe.md)

### Registry & System Operations
- 📝 [reg.py](reg.md)
- 📝 [registry-read.py](registry-read.md)
- 📝 [services.py](services.md)
- 📝 [ntfs-read.py](ntfs-read.md)

### Information Gathering
- 📝 [lookupsid.py](lookupsid.md)
- 📝 [samrdump.py](samrdump.md)
- 📝 [netview.py](netview.md)
- 📝 [net.py](net.md)
- 📝 [machine_role.py](machine_role.md)

### Network Analysis & Monitoring
- 📝 [sniff.py](sniff.md)
- 📝 [sniffer.py](sniffer.md)
- 📝 [kintercept.py](kintercept.md)
- 📝 [karmaSMB.py](karmaSMB.md)

### Utilities & Miscellaneous
- 📝 [ping.py](ping.md)
- 📝 [ping6.py](ping6.md)
- 📝 [split.py](split.md)
- 📝 [exchanger.py](exchanger.md)
- 📝 [esentutl.py](esentutl.md)
- 📝 [getArch.py](getArch.md)
- 📝 [getPac.py](getPac.md)
- 📝 [describeTicket.py](describeTicket.md)
- 📝 [tstool.py](tstool.md)
- 📝 [mqtt_check.py](mqtt_check.md)
- 📝 [rdp_check.py](rdp_check.md)
- 📝 [wmiquery.py](wmiquery.md)

## 🔧 Development Tools
- 🛠️ [generate_docs.py](generate_docs.py) - Documentation generator script

## 📈 Prioritized Enhancement List

### High Priority (Most Used Tools)
1. **smbexec.py** - Alternative to psexec
2. **dcomexec.py** - DCOM-based execution  
3. **GetADUsers.py** - AD user enumeration
4. **atexec.py** - Scheduled task execution
5. **dacledit.py** - DACL modification

### Medium Priority (Specialized Tools)
1. **mssqlclient.py** - Database access
2. **rpcdump.py** - RPC enumeration
3. **reg.py** - Registry operations
4. **services.py** - Service management
5. **ticketer.py** - Ticket creation

### Lower Priority (Utility Tools)
1. **ping.py** - Network utilities
2. **split.py** - File utilities
3. **getArch.py** - System information
4. **tstool.py** - Terminal services

## 🎯 Completion Roadmap

### Phase 1 (High Priority Tools)
- [ ] Complete detailed documentation for top 10 most-used tools
- [ ] Add comprehensive attack chain examples
- [ ] Include detection evasion techniques

### Phase 2 (Specialized Tools)
- [ ] Document database access tools
- [ ] Add network enumeration tools
- [ ] Include system administration tools

### Phase 3 (Utility Tools)
- [ ] Document remaining utility tools
- [ ] Add cross-references between tools
- [ ] Include troubleshooting guides

### Phase 4 (Enhancement)
- [ ] Add video demonstrations
- [ ] Create cheat sheets
- [ ] Add defensive countermeasures

## 🎨 Documentation Standards

### ✅ Complete Documentation Includes:
- Comprehensive overview and description
- Full command-line options
- Multiple usage examples
- Attack chain integration
- Prerequisites and requirements
- Detection considerations
- Defensive measures
- Troubleshooting section
- Related tools cross-references

### 📝 Template Documentation Includes:
- Basic overview (needs expansion)
- Template command-line options
- Basic usage examples (needs customization)
- Template attack chains (needs specifics)
- Standard sections requiring customization

## 🚀 Quick Start for Contributors

### To Enhance Template Documentation:
1. Choose a tool from the template list
2. Read the tool's source code in `/examples/`
3. Run the tool with `-h` to see all options
4. Replace template content with specific information
5. Add real-world examples and attack chains
6. Test all examples for accuracy

### To Add New Tools:
1. Use `generate_docs.py` to create new templates
2. Follow the established documentation format
3. Include comprehensive examples and use cases

---

## 📞 Need Help?

- Check existing detailed documentation for formatting examples
- Review `QUICK_REFERENCE.md` for common patterns  
- Use `generate_docs.py` for new tool templates
- Follow attack chain examples in `ATTACK_METHODOLOGIES.md`

*This index will be updated as documentation is enhanced and completed.*
