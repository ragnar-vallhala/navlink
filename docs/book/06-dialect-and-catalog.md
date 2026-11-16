# Chapter 6. The dialect and the message catalog

## 6.1 The dialect file

`dialect.json` holds three things: a `sections` tree used only for documentation,
a list of `enums`, and the list of `messages`. The version in the file today is
dialect `vayu-core`, version 2, with 15 enums and 57 messages.

A message looks like this:

```
{
  "msgid":   integer (0 .. 16777215),
  "name":    "UPPER_SNAKE", unique,
  "section": dotted path into the sections tree, e.g. "flight.tuning",
  "doc":     optional description,
  "fields":  [ ordered array of fields ]
}
```

and each field has an `index`, a `name`, a `type`, and optionally `len`, `scale`,
`unit`, `enum`, `default`, `extension` and `doc`.

## 6.2 Authoring rules

The rules the generator enforces, and the reasons for them:

- **Fields are an ordered array**, never a name-to-type map, because JSON object
  order is not guaranteed and the wire order matters.
- **Every field has an explicit integer index**, unique within the message and
  contiguous from 0 across the non-extension fields. Extension fields continue
  the numbering. The generator assigns indices to new fields and then freezes
  them into the file, so the layout stays stable.
- **Every field declares a known type.** An unknown or missing type is an error.
- **Fixed-point fields** declare a `scale` and a `unit` next to an integer type.
- **64-bit constants** are written as hex strings, because JSON numbers cannot
  hold all 64-bit values exactly.
- **Core ids are 0x000000 to 0x7FFFFF**; vendor and experimental dialects use
  0x800000 to 0xFFFFFF (chapter 3).
- **Every message and enum names a section.** Sections are for documentation
  only. They never enter the wire format or CRC_EXTRA, so moving a message
  between sections is not an ABI change.

`dialect.schema.json` is the JSON Schema the file must satisfy, and the generator
also checks the rules above before it writes anything.

## 6.3 The catalog by section

The 57 messages in the current dialect, grouped by the dialect's own sections:

| Section | Count | Messages |
|---|---|---|
| Link and system | 12 | HEARTBEAT, SYSTEM_HEALTH, FLIGHT_MODE, STATUSTEXT, FAULT_STATUS, COMMAND_ACK, PING, CAPABILITIES, TIME_SYNC, CMD_ARM, CMD_DISARM, CMD_SET_FLIGHT_MODE |
| Flight: sensors | 5 | IMU_RAW, IMU_COMPRESSED, RC_CHANNELS, BARO, BATTERY |
| Flight: state and control | 5 | ATTITUDE_EULER, MOTOR_TELEMETRY, CONTROL_TRACE, VERTICAL_STATE, NOTCH_STATUS |
| Flight: tuning and filters | 5 | CMD_SET_PID, CMD_SET_GYRO_LPF, CMD_SET_D_LPF, CMD_SET_GYRO_NOTCH, CMD_SET_MOTOR_GEOMETRY |
| Flight: calibration | 2 | CMD_CALIBRATE_IMU, CALIBRATION_STATUS |
| Flight: system ID | 3 | SYSID_SAMPLE, CMD_SYSID_EXCITE, CMD_SYSID_DUMP |
| Storage: file transfer | 6 | XFER_OPEN, XFER_CLOSE, XFER_INFO, XFER_DATA, XFER_ACK, XFER_SACK |
| Storage: filesystem | 5 | FS_LIST, FS_INFO, FS_DELETE, FS_ENTRY, FS_INFO_REPLY |
| Storage: parameters | 4 | PARAM_REQUEST_LIST, PARAM_REQUEST_READ, PARAM_VALUE, PARAM_SET |
| Diagnostics: performance | 7 | EST_PERF, PERF_GLOBAL, PERF_TASK, PERF_FIFO, PERF_TASKNAME_REQUEST, PERF_TASKNAME, HSL_STATUS |
| Diagnostics: hardware test | 3 | HW_TEST_BEGIN, HW_TEST_RESULT, HW_TEST_DONE |

Three observations from the file itself:

- The three hardware-test messages use ids 0x800000 to 0x800002, in the
  vendor/experimental half of the id space, so they are a working example of a
  message that is not core.
- Commands have ids from 8192 upward and sit in the sections of what they
  affect (for example CMD_SET_PID is under tuning). A command's section is not
  its id block.
- The specification's own catalog (its section 14) is organised by id block and
  has blocks (navigation, power, peripherals) for which the current dialect
  defines no message. When the two differ, `dialect.json` is the truth, because
  it is what the generator reads.

## 6.4 Where to read a message's fields

For field-level detail, use `dialect.json` itself, or the per-message pages in
`docs/reference/messages/`. Those pages cover attitude, command, data frame,
file system navigation, heartbeat, IMU data, PID telemetry, RC channels, stream
rates, system status, time sync and transfer. Some of them carry a note that they
were updated for v2 and point to the dialect as authoritative: if a page and the
dialect disagree, trust the dialect.

The generator can also write an HTML tree of the sections and messages
(`python3 generate.py --lang html`). That is a build output and is not
committed.

## Sources

- `dialect.json`, `dialect.schema.json`
- `docs/reference/navlink-v2-spec.md`, sections 7 (the dialect), 9 and 14 (message catalog)
- `docs/reference/messages/*.md`
- `README.md`
