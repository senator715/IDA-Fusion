![Logo](https://user-images.githubusercontent.com/89423559/170590973-86a0c0dd-2052-49a6-bf03-b2178754c3f6.png)
# IDA-Fusion
IDA-Fusion is an ULTRA Fast Signature scanner & creator for IDA7 & IDA8+ using GCC.

# Why IDA-Fusion?
This project was written due to the lack of stable and working signature scanners/creators available for IDA as a whole, Many of these projects are filled with bugs and create signatures that are not guaranteed to be unique. They are slow and tend to have trouble generating signatures in binaries where parts of the binary have been duplicated to prevent reverse engineering and reliable signature creation.

Some of the highlights of IDA-Fusion project:
- Uses GCC
- Very efficient creation and search algorithms.
- Signatures are guaranteed to be unique while delivering minimal size.
- Search for signatures quickly through large binaries.
- The ability to search using IDA & Code signatures.
- Auto jump to signatures found in a binary.
- Created signatures are automatically copied to the clipboard.
- Minimal bloat to increase productivity and speed when using IDA-Fusion.

# How does IDA-Fusion's signature creation work?
IDA-Fusion works by wild-carding any operand that contains an IMM (Immediate value), For instance, IDA-Fusion will signature the following instruction `lea rax, [rbx+10h]` explicitly as `lea rax, [rbx+?]`, However this does not work entirely the same way a usual signature creator would.

Highlighted in blue, demonstrates what is ommitted when a signature is created:
![yb2E5w5](https://user-images.githubusercontent.com/89423559/170587870-133ff3c1-e95a-4a20-a9ca-deb1390cbd40.png)

Creating signatures like this ensures that only the opcodes themselves are sigged, this process IDA-Fusion does differ greatly from other signature creation plugins. And is very good at creating reliable signatures for programs that are specifically attempting to implement anti-signature environments.

# Whats planned next?
We plan to work on many other features and further enhance and optimise IDA-Fusion as much as physically possible. We are always looking for those who are willing to contribute to the project.

Some of the future features planned are:
- CRC Signature generation.
- Reverse searching to create even smaller signatures. (Would be an option)
- Reference based signatures. (Would be an option)
- ~~Configuration dialog for toggling future and experimental features.~~
- Many other features.

# Requirements
- IDA 7.5 And above

# How to install

1. Download the latest [Release here](https://github.com/senator715/IDA-Fusion/releases) or compile yourself.
2. Drag `fusion.dll` and `fusion64.dll` into your IDA installations `plugin` folder.
3. You can access the fusion action menu via `Edit > Plugins > Fusion` or the hotkey `CTRL + ALT + S`

# How to compile

## Using make
1. Download GCC (Preferably MSYS2)
2. Drag your IDA's `idasdk7.x.zip` contents into the `sdk` folder in IDA-Fusion
3. To avoid confusion, it is advisable to modify the copy directories in the following files: `compile32.bat` and `compile64.bat`
4. To compile IDA-Fusion for x86 & x64 IDA. run `compile.bat`

## Using Visual Studio
**Initial support cannot compile for x86 and has not been tested for IDA SDK versions lower to 9.0!**
1. Drag your IDA's `idasdk90.7z` contents into the `sdk` folder in IDA-Fusion
2. Set platform to x64 and compile
3. Compiled files will be written to the `out` folder

# Contributions

You are welcome to contribute to IDA-Fusion project and any help and advice would be greatly appreciated.
