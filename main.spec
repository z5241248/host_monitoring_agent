# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(['./main.py'],
             pathex=['../agent_plugins'],
             binaries=[],
             datas=[('./agent_utils', '.'),
                   ('./linux', 'linux'),
                   ('./win', 'win'),
                   ('./agent.ico', '.'),
                   ('./weak_password', '.')],
             hiddenimports=['requests','pywin32','pypiwin32','win32timezone'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='agent',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          icon='./agent.ico',
          console=True)