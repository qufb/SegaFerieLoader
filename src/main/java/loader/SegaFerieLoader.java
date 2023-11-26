/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.Option;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SegaFerieLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Sega Ferie Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);

		Set<String> knownHashes = Set.of(
			"491e23902f5ef0dea9156f244f5aa2a21ab68505", // mpr-17062-t.ic2
			"73ff933ba2bacd485cbc0580b023341fffac692f"  // mpr-18080a.u2
		);
		byte[] bytes = provider.readBytes(0, provider.length());
		byte[] hashBytes;
		try {
			hashBytes = MessageDigest.getInstance("SHA-1").digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		String hash;
		try (Formatter formatter = new Formatter()) {
			for (byte b : hashBytes) {
				formatter.format("%02x", b);
			}
			hash = formatter.toString();
		}
		boolean isLoaded = knownHashes.stream().anyMatch(knownHash -> knownHash.equalsIgnoreCase(hash));
		if (isLoaded) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("T6A84:LE:16:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider,
			LoadSpec loadSpec,
			List<Option> options,
			Program program,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		InputStream romStream = provider.getInputStream(0);
		long bank_size = 0x10000L;
		createSegment(fpa, null, "DATA", "data:0", 0x10000L, true, true, false, false, false, log);
		createSegment(fpa, null, "IO",   "io:0",   0x00100L, true, true, false, true, false, log);
		for (int i = 0; i < 0x10; i++) {
			createSegment(fpa, provider.getInputStream(Math.min(romStream.available(), bank_size * i)),
					"ROM_" + String.format("%02d", i), "ram:0", bank_size, true, false, true, false, true, log);
			if (romStream.available() <= bank_size * (i + 1)) {
				break;
			}
		}

		createNamedData(fpa,  program, "io:0xe4", "LCD_CTRL", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xe5", "LCD_DATA", ByteDataType.dataType, log);

		createNamedData(fpa,  program, "io:0xf4", "RTC", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xf5", "TABLET_BUTTONS", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xf6", "TABLET_CTRL", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xf7", "TABLET_DATA", ByteDataType.dataType, log);

		createNamedData(fpa,  program, "io:0xfc", "STACK_PAGE", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xfd", "DATA_PAGE", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xfe", "CODE_PAGE", ByteDataType.dataType, log);
		createNamedData(fpa,  program, "io:0xff", "VECTOR_PAGE", ByteDataType.dataType, log);

		// Always use language defined labels, regardless of APPLY_LABELS_OPTION_NAME...
		List<AddressLabelInfo> labels = loadSpec.getLanguageCompilerSpec().getLanguage().getDefaultSymbols();
		for (AddressLabelInfo info : labels) {
			try {
				// ...but only interrupt vectors.
				final long offset = info.getAddress().getUnsignedOffset();
				if (offset > 0x100) {
					continue;
				}
				final Address romAddress = fpa.getAddressFactory().getAddress(
						String.format("ROM_00::%02x", info.getAddress().getUnsignedOffset()));
				//final Address romAddress = info.getAddress();
				program.getSymbolTable().createLabel(romAddress, info.getLabel(), SourceType.IMPORTED);
				new DisassembleCommand(romAddress, null, true).applyTo(program);
			} catch (InvalidInputException e) {
				log.appendException(e);
			}
		}

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			String address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			boolean overlay,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.getAddressFactory().getAddress(address), stream, size, overlay);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			String address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.getAddressFactory().getAddress(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			int numElements,
			DataType type,
			MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			int rwx,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead((rwx & 0b100) != 0);
			block.setWrite((rwx & 0b010) != 0);
			block.setExecute((rwx & 0b001) != 0);
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
