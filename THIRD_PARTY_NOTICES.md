# Third-Party Notices

J0Witness is distributed under the MIT License (see [LICENSE](LICENSE)). The
compiled `j0witness` binary statically links the third-party Go modules listed
below. All of them are under permissive licenses (MIT, BSD-3-Clause, Apache-2.0)
that are compatible with distribution under the MIT License. There are **no**
copyleft-viral (GPL/LGPL/AGPL) dependencies, and no MPL-licensed code is linked
into the binary.

Exact versions are pinned in `src/go.mod` / `src/go.sum`. Each dependency's own
repository contains its full copyright notice and license text; the standard
bodies of the three licenses used are reproduced at the end of this file.

This list reflects the modules actually compiled into the binary
(`go list -deps ./cmd/j0witness`); build-time-only tooling of the pure-Go SQLite
driver (e.g. the modernc C-to-Go transpiler and its dependencies, one of which is
MPL-2.0) is **not** part of the distributed binary.

## Dependencies

| Module | Version | License |
|--------|---------|---------|
| github.com/dustin/go-humanize | v1.0.1 | MIT |
| github.com/gabriel-vasile/mimetype | v1.4.15 | MIT |
| github.com/go-pdf/fpdf | v0.9.0 | MIT |
| github.com/glaslos/tlsh | v0.4.0 | Apache-2.0 |
| github.com/spf13/cobra | v1.10.2 | Apache-2.0 |
| gopkg.in/yaml.v3 | v3.0.1 | MIT and Apache-2.0 |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/hexops/gotextdiff | v1.0.3 | BSD-3-Clause |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause |
| github.com/spf13/pflag | v1.0.9 | BSD-3-Clause |
| golang.org/x/sync | v0.22.0 | BSD-3-Clause |
| golang.org/x/sys | v0.46.0 | BSD-3-Clause |
| modernc.org/libc | v1.74.1 | BSD-3-Clause |
| modernc.org/mathutil | v1.7.1 | BSD-3-Clause |
| modernc.org/memory | v1.11.0 | BSD-3-Clause |
| modernc.org/sqlite | v1.54.0 | BSD-3-Clause |

### By license

- **MIT** — dustin/go-humanize, gabriel-vasile/mimetype, go-pdf/fpdf (and the
  MIT-licensed portions of gopkg.in/yaml.v3).
- **Apache-2.0** — glaslos/tlsh, spf13/cobra, gopkg.in/yaml.v3.
- **BSD-3-Clause** — google/uuid, hexops/gotextdiff, remyoudompheng/bigfft,
  spf13/pflag, golang.org/x/sync, golang.org/x/sys, modernc.org/{libc, mathutil,
  memory, sqlite}. The `golang.org/x/*` modules are © The Go Authors; the
  `modernc.org/*` modules are © the modernc.org authors.

---

## License texts

### The MIT License (MIT)

Applies to the MIT-licensed modules above. Each such module carries its own
copyright line in its upstream `LICENSE` file; the permission grant is:

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### The 3-Clause BSD License (BSD-3-Clause)

Applies to the BSD-3-Clause modules above (each with its own copyright holder,
e.g. "Copyright (c) 2009 The Go Authors. All rights reserved." for the
`golang.org/x/*` modules).

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   3. Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### The Apache License, Version 2.0

Applies to the Apache-2.0 modules above. Full text:
<https://www.apache.org/licenses/LICENSE-2.0>

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

The complete Apache-2.0 text (including the TERMS AND CONDITIONS sections 1–9 and
the appendix) is available at the URL above and is included verbatim in each
Apache-2.0 dependency's `LICENSE` file. Apache-2.0 requires preserving copyright,
patent, trademark, and attribution notices, and stating significant changes;
J0Witness makes no modifications to these dependencies.

---

*Generated by enumerating the modules linked into the compiled binary and
verifying each module's license from its distributed `LICENSE` file. If you
regenerate the dependency set, re-verify with a tool such as
`go install github.com/google/go-licenses@latest && go-licenses report ./...`
from `src/`.*
