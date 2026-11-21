# CIS Apple macOS 15 Sequoia

Checks for the recommendations of the CIS Apple macOS 15 benchmark, taken from the rules of the macOS Security Compliance Project (mSCP). Many rules verify settings delivered by configuration profiles (MDM), as mSCP does. The checks need root, like mSCP itself: run with sudo. Select levels with `--tags cis-level-1` or `--tags cis-level-2`.

**Policy:** [`cis/macos15.yml`](https://github.com/rtulke/checkmate/blob/main/cis/macos15.yml) · **Benchmark version:** Sequoia Guidance, Revision 4.0

The checks read system settings and configuration profiles and need root:

```bash
sudo checkmate run cis/macos15.yml --tags cis-level-1
sudo checkmate run cis/macos15.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-MACOS15-1.1-system_settings_softwareupdate_current` | Ensure Software Update is Updated and Current | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.2-system_settings_software_update_enforce` | Enforce Software Update Automatically | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.3-system_settings_software_update_download_enforce` | Enforce Software Update Downloads Updates Automatically | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.4-system_settings_install_macos_updates_enforce` | Enforce macOS Updates are Automatically Installed | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.5-system_settings_software_update_app_update_enforce` | Enforce Software Update App Update Updates Automatically | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.6-os_config_data_install_enforce` | Enforce Installation of XProtect Remediator and Gatekeeper Updates Automatically | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.6-system_settings_critical_update_install_enforce` | Enforce Critical Security Updates to be Installed | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.7-os_software_update_deferral` | Ensure Software Update Deferment Is Less Than or Equal to $ODV Days | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-1.8-os_mdm_require` | Enforce Enrollment in Mobile Device Management | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.1.1.3-icloud_sync_disable` | Disable iCloud Desktop and Document Folder Sync | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.2.1-system_settings_firewall_enable` | Enable macOS Application Firewall | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.2.2-system_settings_firewall_stealth_mode_enable` | Enable Firewall Stealth Mode | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.1.1-os_airdrop_disable` | Disable AirDrop | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.1.2-system_settings_airplay_receiver_disable` | Disable Airplay Receiver | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.2.1-system_settings_time_server_configure` | Configure macOS to Use an Authorized Time Server | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.2.1-system_settings_time_server_enforce` | Enforce macOS Time Synchronization | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.2.2-os_time_server_enabled` | Enable Time Synchronization Daemon | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.1-system_settings_screen_sharing_disable` | Disable Screen Sharing and Apple Remote Desktop | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.2-system_settings_smbd_disable` | Disable Server Message Block Sharing | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.3-system_settings_printer_sharing_disable` | Disable Printer Sharing | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.4-system_settings_ssh_disable` | Disable SSH Server for Remote Access Sessions | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-2.3.3.5-system_settings_remote_management_disable` | Disable Remote Management | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.6-system_settings_rae_disable` | Disable Remote Apple Events | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.7-system_settings_internet_sharing_disable` | Disable Internet Sharing | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.8-system_settings_content_caching_disable` | Disable Content Caching Service | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.9-system_settings_media_sharing_disabled` | Disable Media Sharing | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.3.10-system_settings_bluetooth_sharing_disable` | Disable Bluetooth Sharing | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.3.4.1-system_settings_time_machine_auto_backup_enable` | Configure Time Machine for Automatic Backups | L2 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-2.3.4.2-system_settings_time_machine_encrypted_configure` | Ensure Time Machine Volumes are Encrypted | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.4.1-system_settings_wifi_menu_enable` | Enable Wifi Menu | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.4.2-system_settings_bluetooth_menu_enable` | Enable Bluetooth Menu | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.1-system_settings_external_intelligence_disable` | Disable External Intelligence Integrations | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.1-system_settings_external_intelligence_sign_in_disable` | Disable External Intelligence Integration Sign In | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.2-os_writing_tools_disable` | Disable Apple Intelligence Writing Tools | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.3-os_mail_summary_disable` | Disable Apple Intelligence Mail Summary | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.4-os_notes_transcription_disable` | Disable Apple Intelligence Notes Transcription | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.1.4-os_notes_transcription_summary_disable` | Disable Apple Intelligence Notes Transcription Summary | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.5.2.1-system_settings_siri_disable` | Disable Siri | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.1.1-system_settings_location_services_enable` | Enable Location Services | L2 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-2.6.1.2-system_settings_location_services_menu_enforce` | Ensure Location Services Is In the Menu Bar | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.3.1-system_settings_diagnostics_reports_disable` | Disable Sending Diagnostic and Usage Data to Apple | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.3.2-system_settings_improve_siri_dictation_disable` | Disable Improve Siri and Dictation Information to Apple | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.3.3-system_settings_improve_assistive_voice_disable` | Disable Sending Audio Recordings and Transcripts to Apple | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.4-system_settings_personalized_advertising_disable` | Disable Personalized Advertising | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.6.5-os_gatekeeper_enable` | Enable Gatekeeper | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-2.6.6-system_settings_filevault_enforce` | Enforce FileVault | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-2.6.8-system_settings_system_wide_preferences_configure` | Require Administrator Password to Modify System-Wide Preferences | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-2.7.1-system_settings_hot_corners_secure` | Secure Hot Corners | L2 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-2.9.1-system_settings_improve_search_disable` | Disable Improve Search Information to Apple | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.10.1.1-os_sleep_and_display_sleep_apple_silicon_enable` | Ensure Sleep and Display Sleep Is Enabled on Apple Silicon Devices | L2 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-2.10.2-os_power_nap_disable` | Disable Power Nap | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.10.3-system_settings_wake_network_access_disable` | Ensure Wake for Network Access Is Disabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.11.1-system_settings_screensaver_timeout_enforce` | Enforce Screen Saver Timeout | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.11.2-system_settings_screensaver_ask_for_password_delay_enforce` | Enforce Session Lock After Screen Saver is Started | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.11.4-system_settings_loginwindow_prompt_username_password_enforce` | Configure Login Window to Prompt for Username and Password | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.11.5-system_settings_password_hints_disable` | Disable Password Hints | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.12.1-os_password_hint_remove` | Remove Password Hint From User Accounts | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.13.1-system_settings_guest_account_disable` | Disable the Guest Account | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.13.2-system_settings_guest_access_smb_disable` | Disable Guest Access to Shared SMB Folders | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.13.3-system_settings_automatic_login_disable` | Disable Unattended or Automatic Logon to the System | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-2.18.1-os_on_device_dictation_enforce` | Enforce On Device Dictation | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.1-audit_auditd_enabled` | Enable Security Auditing | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_aa_configure` | Configure System to Audit All Authorization and Authentication Events | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_ad_configure` | Configure System to Audit All Administrative Action Events | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_ex_configure` | Configure System to Audit All Failed Program Execution on the System | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_fm_failed_configure` | Configure System to Audit All Failed Change of Object Attributes | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_fr_configure` | Configure System to Audit All Failed Read Actions on the System | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_fw_configure` | Configure System to Audit All Failed Write Actions on the System | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.2-audit_flags_lo_configure` | Configure System to Audit All Log In and Log Out Events | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.3-os_install_log_retention_configure` | Configure Install.log Retention to $ODV | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.4-audit_retention_configure` | Configure Audit Retention to $ODV | L1 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-3.5-audit_acls_files_configure` | Configure Audit Log Files to Not Contain Access Control Lists | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_acls_folders_configure` | Configure Audit Log Folder to Not Contain Access Control Lists | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_control_acls_configure` | Configure Audit_Control to Not Contain Access Control Lists | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_control_group_configure` | Configure Audit_Control Group to Wheel | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_control_mode_configure` | Configure Audit_Control Owner to Mode 440 or Less Permissive | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_control_owner_configure` | Configure Audit_Control Owner to Root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_files_group_configure` | Configure Audit Log Files Group to Wheel | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_files_mode_configure` | Configure Audit Log Files to Mode 440 or Less Permissive | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_files_owner_configure` | Configure Audit Log Files to be Owned by Root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_folder_group_configure` | Configure Audit Log Folders Group to Wheel | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_folder_owner_configure` | Configure Audit Log Folders to be Owned by Root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-3.5-audit_folders_mode_configure` | Configure Audit Log Folders to Mode 700 or Less Permissive | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-4.1-os_bonjour_disable` | Disable Bonjour Multicast | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-4.2-os_httpd_disable` | Disable the Built-in Web Server | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-4.3-os_nfsd_disable` | Disable Network File System Service | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.1-os_home_folders_secure` | Secure User's Home Folders | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.2-os_sip_enable` | Ensure System Integrity Protection is Enabled | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-5.1.3-os_mobile_file_integrity_enable` | Enable Apple Mobile File Integrity | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.4-os_authenticated_root_enable` | Enable Authenticated Root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.5-os_system_wide_applications_configure` | Ensure Appropriate Permissions Are Enabled for System Wide Applications | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.6-os_world_writable_system_folder_configure` | Ensure No World Writable Files Exist in the System Folder | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.1.7-os_world_writable_library_folder_configure` | Ensure No World Writable Files Exist in the Library Folder | L2 | <span class="sev sev-low">low</span> |
| `CIS-MACOS15-5.2.1-pwpolicy_account_lockout_enforce` | Limit Consecutive Failed Login Attempts to $ODV | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.1-pwpolicy_account_lockout_timeout_enforce` | Set Account Lockout Time to $ODV Minutes | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.2-pwpolicy_minimum_length_enforce` | Require a Minimum Password Length of $ODV Characters | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.3-pwpolicy_alpha_numeric_enforce` | Require Passwords Contain a Minimum of One Numeric Character | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.5-pwpolicy_special_character_enforce` | Require Passwords Contain a Minimum of One Special Character | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.6-pwpolicy_custom_regex_enforce` | Require Passwords to Match the Defined Custom Regular Expression | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.7-pwpolicy_max_lifetime_enforce` | Restrict Maximum Password Lifetime to $ODV Days | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.2.8-pwpolicy_history_enforce` | Prohibit Password Reuse for a Minimum of $ODV Generations | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.4-os_sudo_timeout_configure` | Configure Sudo Timeout Period to $ODV | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.5-os_sudoers_timestamp_type_configure` | Configure Sudoers Timestamp Type | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.6-os_root_disable` | Disable Root Login | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.7-os_unlock_active_user_session_disable` | Disable Login to Other User's Active and Locked Sessions | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.8-os_policy_banner_loginwindow_enforce` | Display Policy Banner at Login Window | L2 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.9-os_guest_folder_removed` | Remove Guest Folder if Present | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-5.10-os_anti_virus_installed` | Must Use an Approved Antivirus Program | L1 | <span class="sev sev-high">high</span> |
| `CIS-MACOS15-5.11-os_sudo_log_enforce` | Configure Sudo To Log Events | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.1.1-os_show_filename_extensions_enable` | Enable Show All Filename Extensions | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.1-os_safari_open_safe_downloads_disable` | Disable Automatic Opening of Safe Files in Safari | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.3-os_safari_warn_fraudulent_website_enable` | Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.4-os_safari_prevent_cross-site_tracking_enable` | Ensure Prevent Cross-site Tracking in Safari Is Enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.6-os_safari_advertising_privacy_protection_enable` | Ensure Advertising Privacy Protection in Safari Is Enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.7-os_safari_show_full_website_address_enable` | Ensure Show Full Website Address in Safari Is Enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.3.10-os_safari_show_status_bar_enabled` | Ensure Show Safari shows the Status Bar is Enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-MACOS15-6.4.1-os_terminal_secure_keyboard_enable` | Ensure Secure Keyboard Entry Terminal.app is Enabled | L1 | <span class="sev sev-medium">medium</span> |
