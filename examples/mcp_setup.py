"""Generate local-client configuration fragments and optionally probe stdio.

Run with the Python environment where aibom-guardian is installed.
Does not edit client settings. Each output directory must be new.
"""
import argparse
import asyncio
from datetime import timedelta
import json
from pathlib import Path
import sys


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


async def probe(configs, output):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    expected = {'check_package', 'check_license', 'check_model', 'check_repo_trust'}
    summary = {'scope': 'SDK stdio probe, not GUI client verification', 'clients': {}}
    for name, config in configs.items():
        entry = config.get('mcpServers', config.get('servers'))['aibom-guardian']
        record = {'passed': False}
        try:
            params = StdioServerParameters(command=entry['command'], args=entry['args'], cwd=str(output))
            with (output / (name + '.stderr.log')).open('w', encoding='utf-8') as log:
                async with stdio_client(params, errlog=log) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=90)) as session:
                        initialized = await session.initialize()
                        listing = await session.list_tools()
                        save(output / (name + '.tools.json'), listing.model_dump(mode='json'))
                        names = {tool.name for tool in listing.tools}
                        record.update(protocol=initialized.protocolVersion, tools=sorted(names))
                        if names != expected:
                            raise RuntimeError('Unexpected tool inventory')
                        for label, tool, arguments in [
                            ('license', 'check_license', {'license_string': 'MIT'}),
                            ('unsupported', 'check_package', {'name': 'lodash', 'version': '4.17.20', 'ecosystem': 'npm'}),
                        ]:
                            response = await session.call_tool(tool, arguments)
                            save(output / (name + '.' + label + '.json'), response.model_dump(mode='json'))
                            data = response.structuredContent
                            if data is None:
                                data = json.loads(next(c.text for c in response.content if c.type == 'text'))
                            if response.isError:
                                raise RuntimeError('MCP transport tool error: ' + label)
                            if label == 'license':
                                if not data.get('success') or data.get('status') != 'ALLOWED':
                                    raise RuntimeError('MIT classification did not return ALLOWED')
                            elif data.get('success') is not False:
                                raise RuntimeError('Unsupported ecosystem was not rejected')
                        record['passed'] = True
        except Exception as exc:
            record['error_type'] = type(exc).__name__
            # Details remain in local stderr; do not serialize credentials or URLs from exceptions.
        summary['clients'][name] = record
        save(output / 'summary.json', summary)
    print(json.dumps(summary, indent=2))
    return all(r['passed'] for r in summary['clients'].values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New directory for configuration fragments and evidence')
    parser.add_argument('--check', action='store_true', help='Start each configured command using the MCP SDK')
    args = parser.parse_args()
    import aibom_guardian  # Verify that this interpreter has the product installed.

    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    # Do not resolve a Unix venv Python symlink to its base interpreter.
    server = {'command': str(Path(sys.executable).absolute()),
              'args': ['-I', '-X', 'utf8', '-m', 'aibom_guardian.mcp_server']}
    configs = {
        'claude-desktop': {'mcpServers': {'aibom-guardian': server}},
        'cursor': {'mcpServers': {'aibom-guardian': {'type': 'stdio', **server}}},
        'vscode': {'servers': {'aibom-guardian': {'type': 'stdio', **server}}},
    }
    for name, config in configs.items():
        save(output / (name + '.json'), config)
    save(output / 'environment.json', {'python': sys.version, 'executable': sys.executable,
                                      'package': aibom_guardian.__file__})
    print('Configuration fragments: ' + str(output), flush=True)
    if args.check and not asyncio.run(probe(configs, output)):
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
