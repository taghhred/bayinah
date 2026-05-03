# Synthetic OT incident: USB-delivered worm + backdoor

**Classification:** training / demonstration dataset only — not real malware.

## Narrative

1. **Initial access — removable media (T1200)**  
   An operator connects a USB mass-storage device to an engineering workstation on the OT demilitarized zone. The device carries a self-copying payload that autoruns or exploits a trusted path to execute on the host.

2. **Propagation — network worm behavior (T1091 / T1021–style lateral movement)**  
   The payload enumerates reachable hosts (HMI, historians, low-segmentation PLCs gateways) and spreads using weak credentials or exposed services, producing bursty SYN/RST patterns and elevated flows per second typical of automated scanning and replication.

3. **Persistence / re-entry — backdoor & C2 channel (T1071, T1543)**  
   A lightweight backdoor is installed to maintain access after the USB is removed. It opens periodic outbound sessions (moderate `Flow Packets/s`, sustained `Flow Bytes/s`, PSH-heavy small payloads) for command-and-control and future re-entry.

## Dataset file

Use **`ot_usb_worm_backdoor_evidence.csv`** with the same feature schema as the Baunah XGBoost model (`feature_columns.json`), plus `Timestamp` and `Label` for auditing and optional bootstrap training.

## Row groups (high level)

| Phase | Approx. rows | `Label` (illustrative) |
|--------|----------------|-------------------------|
| Baseline OT traffic | 1–8 | Benign |
| USB mount / exfil-style I/O | 9–18 | OT_USB_Initial |
| Lateral spread / scan | 19–35 | OT_Worm_Propagation |
| C2 / backdoor beacon | 36–45 | OT_Backdoor_C2 |

When only binary labels are required, map non-`Benign` rows to **Malicious**.
