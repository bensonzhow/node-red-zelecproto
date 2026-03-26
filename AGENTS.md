# AGENTS.md

This file contains guidelines and commands for agentic coding agents working in the node-red-zelecproto repository.

## Global Settings
- **Proxy**: Execute `proxy` command before running any network-related commands to enable proxy connection

## Build/Test/Lint Commands

### Current Commands
- `npm test` - Currently shows "Error: no test specified" (placeholder)
- No build, lint, or typecheck commands are currently configured

### Testing
- Use `node test.js` to run the manual test file
- Test file located at: `test.js`
- For single test execution, run `node -e "require('./test.js')"`

### Development
- No build process required (Node-RED nodes load directly)
- Manual testing via Node-RED flow editor recommended

## Code Style Guidelines

### File Structure and Naming
- Main node files: `zelecproto.js`, `zbatchproto.js`, `zeleble.js`
- Protocol implementations: `645.js`, `698.js`, `ble.js`
- HTML definitions: `zelecproto.html`, `zbatchproto.html`, `zeleble.html`
- Icons in: `icons/` directory (SVG format)
- Use kebab-case for file names

### Module Pattern
All Node-RED nodes must follow this pattern:
```javascript
module.exports = function (RED) {
    "use strict";
    
    // Require dependencies
    var proto645 = require("./645");
    
    function NodeName(n) {
        RED.nodes.createNode(this, n);
        var node = this;
        
        this.on("input", function (msg, send, done) {
            // Process message
            send(msg);
            done();
        });
        
        this.on('close', () => {
            // Cleanup if needed
        });
    }
    
    RED.nodes.registerType("nodename", NodeName);
}
```

### Import/Require Style
- Use `var` for requires (consistent with existing codebase)
- Local dependencies first: `var proto645 = require("./645");`
- Group requires at top of module function
- Use relative paths for local files

### Code Formatting
- Use strict mode: `"use strict";` at top of module function
- Indentation: 4 spaces (consistent with existing files)
- Semicolons required
- String quotes: single quotes preferred
- Object property access: dot notation for known properties, bracket notation for dynamic

### Naming Conventions
- Node functions: PascalCase (e.g., `zelecproto`, `zbatchproto`)
- Variables: camelCase (e.g., `msg`, `node`, `addrBytes`)
- Constants: UPPER_SNAKE_CASE (e.g., `START`, `END`, `OAD`)
- File names: kebab-case (e.g., `zelecproto.js`, `645.js`)

### Error Handling
- Use `throw new Error()` for validation errors
- Include descriptive error messages
- Validate input parameters before processing
- Example: `if (addrRaw.length !== 12) throw new Error('com_exec_addr 必须是 6 字节(12个HEX字符)');`

### Message Processing
- Always use the three-parameter input handler: `function (msg, send, done)`
- Call `send(msg)` before `done()`
- Clean up temporary properties: `delete msg._proto`
- Preserve original message structure when possible

### Protocol Implementation
- 645 Protocol: Focus on DL/T 645 frame building/parsing
- 698 Protocol: DL/T 698.45 encode/decode with CRC-16/X-25
- BLE Protocol: 国网多芯物联表蓝牙通信协议
- Each protocol file should export a function that takes `msg` and returns modified `msg`

### HTML Node Definitions
- Use data-template-name attribute matching node type
- Include name field in all nodes
- Set appropriate category, color, and icon
- Category: 'zutils' for all nodes
- Icons: reference SVG files in icons/ directory

### Comments and Documentation
- Use Chinese comments for protocol-specific explanations (consistent with existing code)
- Use JSDoc-style comments for functions
- Include protocol references and frame format descriptions
- Example: `// 国网多芯物联表《蓝牙通信及脉冲检定说明手册(0224)》协议`

### Buffer/Hex Handling
- Use `Buffer.from()` for creating buffers
- Hex strings should be uppercase without spaces for final output
- Use helper functions for hex/bytes conversion
- Maintain consistent hex formatting across protocols

### Node-RED Integration
- Register nodes in package.json under `node-red.nodes`
- Minimum Node.js version: >=15
- Minimum Node-RED version: >=1.3
- No external dependencies currently required

## Development Workflow
1. Modify protocol implementation files as needed
2. Test with `node test.js` or via Node-RED flow editor
3. Ensure all nodes follow the standard module pattern
4. Verify HTML definitions match JavaScript node registrations
5. Test message processing with sample data

## Protocol-Specific Notes
- 645: Handle address reversal and OAD encryption
- 698: Implement CRC-16/X-25 checksum validation
- BLE: Follow frame format with Start/End markers
- All protocols should support both encode and decode operations