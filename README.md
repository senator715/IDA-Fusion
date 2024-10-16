![IDA-Fusion Logo](https://user-images.githubusercontent.com/89423559/170590973-86a0c0dd-2052-49a6-bf03-b2178754c3f6.png)

# IDA-Fusion
**IDA-Fusion** is an **ULTRA fast** signature scanner and creator for IDA Pro versions 7 and 8+, powered by GCC.

---

## Why Choose IDA-Fusion?
IDA-Fusion was developed to address the lack of stable and reliable signature scanners and creators available for IDA. Most existing solutions are riddled with bugs, generate non-unique signatures, and struggle with binaries that employ anti-reverse engineering techniques, such as duplicated binary parts.

**IDA-Fusion** stands apart because it is:

- **GCC-Powered**: Built with GCC for reliability and compatibility.
- **Optimized and Fast**: Efficient algorithms for signature creation and scanning, quickly handling large binaries.
- **Compact and Unique**: Keeps signatures small without sacrificing uniqueness.
- **Versatile**: Supports IDA-style, code-style, CRC-32, and FNV1-A signature generation.
- **User-Friendly**: Auto-jumps to matches, copies signatures to clipboard, and keeps things streamlined.

---

## How Does IDA-Fusion Create Signatures?
IDA-Fusion operates by wildcarding any operand that contains an **immediate value (IMM)**. For example, the instruction `lea rax, [rbx+10h]` is converted into the signature `lea rax, [rbx+?]`. This approach differs significantly from traditional signature creators, as it ensures that only the **opcodes** are captured, making IDA-Fusion especially effective for programs designed to resist signature creation.

![Signature Creation Example](https://user-images.githubusercontent.com/89423559/170587870-133ff3c1-e95a-4a20-a9ca-deb1390cbd40.png)

In the image above, the highlighted portion shows what is omitted when creating a signature. By focusing solely on opcodes, IDA-Fusion produces more reliable signatures, especially for binaries that employ anti-signature measures.

---

## What's Next for IDA-Fusion?
We're committed to enhancing and optimizing IDA-Fusion with new features and performance improvements. We're also open to contributions from the community. Some planned future features include:

- **Reverse Searching**: Create even smaller signatures by analyzing from the end (optional feature).
- **Reference-Based Signatures**: Generate signatures based on references (optional feature).
- **More Features**: We're continuously brainstorming additional features to enhance IDA-Fusion.

---

## Requirements
- **IDA Pro Version 7.5 or Above**

---

## Installation

1. **Download the Latest Release**: Get the latest [Release here](https://github.com/senator715/IDA-Fusion/releases), or compile it yourself.
2. **Copy Plugin Files**: Drag `fusion.dll` and `fusion64.dll` into your IDA installation's `plugins` folder.
3. **Access the Fusion Menu**: Use `Edit > Plugins > Fusion` or press `CTRL + ALT + S` to open the action menu.

---

## Compilation Instructions

1. **Download GCC**: Install GCC, preferably using MSYS2.
2. **Extract SDK**: Extract the contents of IDA's `idasdk7.x.zip` into the `sdk` folder within IDA-Fusion.
3. **Modify Copy Directories**: To avoid confusion, update the copy directories in `compile.bat`.
4. **Run the Compilation Script**: Run `compile.bat` to compile IDA-Fusion for both x86 and x64 versions of IDA.

---

## Contributing

We warmly welcome contributions! Whether it's a new feature, bug fix, or advice, your help is greatly appreciated. Join us in making IDA-Fusion even better.

---

Feel free to get in touch if you have any questions or suggestions for improvement. Happy reversing!

