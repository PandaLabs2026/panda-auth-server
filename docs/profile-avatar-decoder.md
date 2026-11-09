# Private profile avatar decoder (draft)

The private profile feature remains disabled by default. This implementation uses
Magick.NET-Q8-x64 15.1.0 as a development candidate. It is not an accepted public
redistribution bundle or a production resource-budget approval.

The decoder runs through `--profile-avatar-decode` before web/configuration
initialization. The parent starts its own executable, passes bytes only over stdin,
clears the environment except runtime/temp/OS essentials, and accepts bounded PNG
output. Database/mail/signing settings are not passed to the worker. No native
image work runs in the web process. Cancellation/deadline kills and reaps the
process before releasing its permit.

One worker is active; two further requests may hold bounded upload buffers.
Admission, upload reading, queue wait and decoding share a 15-second deadline.
Each account is also limited to two upload attempts per minute in PostgreSQL;
malformed uploads consume attempts, and deleting an avatar does not reset them.
Native pixel-cache memory is limited to 64 MiB, map/disk caches to zero and native
threads to one. The separate managed heap limit is 64 MiB. These limits do not
by themselves establish the combined web/worker RSS or container budget.

Input is at most 2 MiB, detected as PNG/JPEG/WebP from bytes. Delegates, filters,
paths and all other coders/modules are denied. Ping rejects multiple frames,
axes above 4096 and more than 4,194,304 pixels before full decode. Warnings fail
closed. PNG chunk allocations are capped at 256 KiB with at most 16 cached chunks;
PNG/WebP animation control is rejected before Ping, including single-frame animation. Orientation is applied, then the image is resized without upscaling to
at most 512 on either axis and encoded as PNG, at most 256 KiB. Metadata is stripped;
only IHDR/PLTE/IDAT/IEND/tRNS chunks from the new encoding survive. The source bytes
are never stored. MIME labels do not select a decoder.

The resolved package's complete `Notice.txt` is copied verbatim to
`ThirdPartyNotices/Magick.NET-15.1.0.txt` in build/publish output. Package SHA-256:
`fb5414292085db2bc28326fa6d73d04d5ed2ec49a0f32cfcd95467a6de6b6a47`.
The Linux native library includes components with obligations beyond the wrapper's
Apache-2.0 license. Corresponding component/source/build/relink materials and the
owning product's third-party review must accompany any applicable redistribution;
copying this notice alone does not fulfill those obligations. Disabling the feature
does not remove native binaries from an artifact. Existing product release gates
remain open until their exact candidate materials are accepted.

Tests cover actual worker roundtrips and process cancellation/reaping, admission,
three formats at the maximum pixel count, dimensions, animation, truncation,
metadata removal, EXIF orientation, persistent limits, PostgreSQL writes and HTTP
privacy/revision headers. Final combined resource and whole-workspace evidence is
owned by the coordinating UX-04 #323 task.
