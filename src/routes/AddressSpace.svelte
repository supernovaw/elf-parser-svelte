<script>
    export let width = "100%";
    export let height = "10em";
    export let arrayBuffer = undefined;
    export let members = undefined;
    export let areas = undefined;

    let canvas;
    let clientWidth, clientHeight;
    let mouseX = 0,
        mouseY = 0,
        mouseFraction = 0,
        mouseAddr = 0;
    let dpr = 1;
    let range = [0, 16];
    let rangeAnimation = {
        duration: 150,
        previous: undefined,
        timestamp: 0,
        expired: true,
    };
    let focusedMembers = [];

    $: canvas && onResize(width, height, dpr, arrayBuffer, members);

    const scopedPaint = () => paint();

    function paint() {
        const g = canvas.getContext("2d");
        g.resetTransform();
        g.scale(dpr, dpr);
        g.clearRect(0, 0, clientWidth, clientHeight);
        g.font = "1em monospace";
        const r = tweenedRange();

        const baseline = Math.round(clientHeight * 0.4);
        const thickness = 16;
        shadeChunks(g, r, baseline, thickness);
        drawBytes(g, r, baseline);

        drawMembers(g, r, baseline, thickness);

        drawAreas(g, r, baseline, thickness);

        if (!rangeAnimation.expired) {
            requestAnimationFrame(scopedPaint);
            mouseMoved({ offsetX: mouseX, offsetY: mouseY });
        }
    }

    function drawMembers(g, r, baseline, thickness) {
        if (!members) return;
        for (let i = 0; i < members.length; i++) {
            const mem = members[i];
            const pos0 = addrToPositionPx(mem.addr, r);
            const pos1 = addrToPositionPx(mem.addr + mem.len, r);
            if (pos1 < 0 || pos0 > clientWidth) continue;
            const y = baseline + thickness + 4;
            const w = pos1 - pos0;
            g.fillStyle = mem.ptr ? "#f24" : mem.memPtr ? "#2a6" : "#fff7";
            g.beginPath();
            g.roundRect(pos0, y, w, 7, 4);
            g.closePath();
            g.fill();
            g.fillStyle = "#fffa";
            g.beginPath();
            g.roundRect(pos0 + 1, y + 1, w - 2, 5, 4);
            g.closePath();
            g.fill();
        }
    }

    function countOverlaps(range, rangesArray) {
        let n = 0;
        rangesArray.forEach((r) => {
            if (r[1] <= range[0] || r[0] >= range[1]) return;
            n++;
        });
        return n;
    }

    function drawAreas(g, r, baseline, thickness) {
        if (!areas) return;

        g.font = "0.5em monospace";
        g.textAlign = "center";
        g.textBaseline = "middle";

        const printedAreaPxRanges = [];

        for (let i = 0; i < areas.length; i++) {
            const area = areas[i];
            const pos0 = addrToPositionPx(area.ptr, r);
            const pos1 = addrToPositionPx(area.ptr + area.len, r);
            if (pos1 < 0 || pos0 > clientWidth) continue;

            const y = baseline + thickness * 2;
            const w = pos1 - pos0;
            g.fillStyle = "#fff2";
            g.beginPath();
            g.roundRect(pos0, y, w, 7, 4);
            g.closePath();
            g.fill();
            g.fillStyle = "#fff2";
            g.beginPath();
            g.roundRect(pos0 + 1, y + 1, w - 2, 5, 4);
            g.closePath();
            g.fill();

            if (g.measureText(area.name).width < w) {
                let shiftDown = countOverlaps([pos0, pos1], printedAreaPxRanges);
                g.fillStyle = "#fff";
                g.fillText(area.name, Math.round((pos0 + pos1) / 2), y + 4 + shiftDown * 8);
                printedAreaPxRanges.push([pos0, pos1]);
            }
        }
        g.font = "1em monospace";
    }

    function drawBytes(g, r, baseline) {
        if (!arrayBuffer) return;
        const span = r[1] - r[0];
        const bytesIn100Px = (span / clientWidth) * 100;
        if (bytesIn100Px > 12) return;

        g.textAlign = "center";
        g.textBaseline = "bottom";

        const bytes = new Uint8Array(arrayBuffer);
        const start = Math.floor(r[0]);
        const end = Math.min(r[1], arrayBuffer.byteLength);
        let previousX = addrToPositionPx(start, r);
        g.font = "0.65em monospace";
        for (let addr = Math.floor(r[0]); addr < end; addr++) {
            const byte = bytes[addr];
            const rightX = addrToPositionPx(addr + 1, r);
            if (byte !== undefined) {
                g.fillStyle = byte === 0 ? "#f24" : "#fff";
                const hex = bytes[addr].toString(16).padStart(2, "0");
                g.fillText(hex, Math.round((previousX + rightX) / 2), baseline);
                if (byte > 32 && byte < 127) {
                    const char = String.fromCharCode(byte);
                    g.fillText(
                        char,
                        Math.round((previousX + rightX) / 2),
                        baseline - 10,
                    );
                }
            }
            previousX = rightX;
        }
        g.font = "1em monospace";
    }

    function shadeChunks(g, r, baseline, thickness) {
        const span = r[1] - r[0];
        const hundredPxSpan = (span / clientWidth) * 100;
        const shadedChunkSize = Math.max(
            1,
            2 ** Math.floor(Math.log2(hundredPxSpan)),
        );
        const start = Math.max(
            0,
            r[0] - (r[0] % (shadedChunkSize * 2)) - shadedChunkSize * 2,
        );
        let alternating = false;
        let previousX = addrToPositionPx(start, r);

        // Fill alternating rectangles
        for (
            let addr = start + shadedChunkSize;
            addr <= r[1] + shadedChunkSize;
            addr += shadedChunkSize
        ) {
            const x = addrToPositionPx(addr, r);
            g.fillStyle = alternating ? "#222" : "#345";
            g.fillRect(previousX, baseline, x - previousX, thickness);
            previousX = x;
            alternating ^= 1;
        }

        if (arrayBuffer) {
            const bufEnd = addrToPositionPx(arrayBuffer.byteLength);
            if (bufEnd < clientWidth) {
                // g.fillStyle = "#000a";
                g.clearRect(
                    bufEnd,
                    baseline,
                    clientWidth - bufEnd,
                    thickness / 2,
                );
            }
        }
        g.textAlign = "end";
        g.textBaseline = "middle";

        const deltaPx =
            addrToPositionPx(start + shadedChunkSize, r) -
            addrToPositionPx(start, r);
        const pad = 10;
        const str =
            humanReadableSizeFull(shadedChunkSize) +
            " = 2^" +
            Math.log2(shadedChunkSize);
        g.fillStyle = "#345";
        g.fillRect(clientWidth - pad - deltaPx, pad, deltaPx, thickness);
        g.fillStyle = "white";
        g.fillText(str, clientWidth - pad, pad + thickness / 2);
    }

    function addrToPositionPx(address, r) {
        r ??= tweenedRange();
        const fraction = (address - r[0]) / (r[1] - r[0]);
        return Math.round(fraction * clientWidth);
    }

    function onResize() {
        clientWidth = canvas.clientWidth;
        clientHeight = canvas.clientHeight;
        canvas.width = clientWidth * dpr;
        canvas.height = clientHeight * dpr;
        scopedPaint();
    }

    function mouseMoved(e) {
        mouseX = e.offsetX;
        mouseY = e.offsetY;
        mouseFraction = e.offsetX / clientWidth;
        mouseAddr = range[0] + mouseFraction * (range[1] - range[0]);
        if (members) {
            focusedMembers = members.filter(
                (m) => m.addr <= mouseAddr && mouseAddr <= m.addr + m.len,
            );
        }
    }

    function tweenedRange() {
        if (rangeAnimation.expired) {
            return range;
        }
        const elapsed = performance.now() - rangeAnimation.timestamp;
        const t = elapsed / rangeAnimation.duration;
        if (t > 1) {
            rangeAnimation.expired = true;
            return range;
        }
        const from = rangeAnimation.previous;
        const to = range;
        const easedT = 1 - Math.pow(1 - t, 3);
        return [
            from[0] + easedT * (to[0] - from[0]),
            from[1] + easedT * (to[1] - from[1]),
        ];
    }

    function wheelScrolled(e) {
        if (e.ctrlKey) return;
        e.preventDefault();
        const currentRange = tweenedRange();
        const currentSpan = currentRange[1] - currentRange[0];
        rangeAnimation.timestamp = performance.now();
        rangeAnimation.expired = false;
        rangeAnimation.previous = currentRange;

        if (e.shiftKey) {
            const shiftFraction = (e.deltaY * window.devicePixelRatio) / 2000;
            range = [
                currentRange[0] + currentSpan * shiftFraction,
                currentRange[1] + currentSpan * shiftFraction,
            ];
            paint();
            return;
        }

        const factor = Math.exp((e.deltaY * window.devicePixelRatio) / 400);
        if (currentSpan < 4 && factor < 1) return;
        if (currentSpan > 1e21 && factor > 1) return;
        const newSpan = currentSpan * factor;

        range = [
            mouseAddr - newSpan * mouseFraction,
            mouseAddr + newSpan * (1 - mouseFraction),
        ];
        paint();
    }

    function mouseClicked(e) {
        mouseMoved(e);
        const reference = focusedMembers.find((m) => m.ptr !== undefined);
        if (reference) {
            const span = range[1] - range[0];
            rangeAnimation.timestamp = performance.now();
            rangeAnimation.expired = false;
            rangeAnimation.previous = range;

            range = [
                reference.ptr + 0.5 - span * mouseFraction,
                reference.ptr + 0.5 + span * (1 - mouseFraction),
            ];
            paint();
        }
    }

    function humanReadableScale(bytes) {
        if (bytes < 1024) return "< 1 KB";
        if (bytes < 65536) return "< 64 KB";
        if (bytes < 1024 * 512) return "< 0.5 MB";
        if (bytes < 1024 * 1024) return "< 1 MB";
        if (bytes < 1024 * 1024 * 16) return "< 16 MB";
        if (bytes < 1024 * 1024 * 256) return "< 256 MB";
        if (bytes < 1024 * 1024 * 1024) return "< 1 GB";
        if (bytes < 1024 * 1024 * 4096) return "< 4 GB";
        if (bytes < 1024 * 1024 * 1024 * 128) return "< 128 GB";
        if (bytes < 1024 * 1024 * 1024 * 1024) return "< 1 TB";
        if (bytes < 1024 * 1024 * 1024 * 1024 * 128) return "< 128 TB";
        return "Enormous";
    }

    function humanReadableSizeFull(bytes) {
        if (bytes === 0) {
            return "zero";
        }
        if (bytes < 0) {
            return "Negative " + humanReadableSizeFull(-bytes);
        }
        const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
        const parts = [];
        while (bytes !== 0) {
            if (units.length === 0) return "stupid-big";
            const rem = bytes % 1024;
            bytes = (bytes - rem) / 1024;
            if (rem !== 0) {
                parts.unshift(rem + units[0]);
            }
            units.shift();
        }
        return parts.join(" ");
    }

    function status(mouseAddr, range, buf, focusedMembers) {
        let result = [];
        const posHuman = humanReadableSizeFull(Math.floor(mouseAddr));
        result.push(
            `Mouse: 0x${Math.floor(mouseAddr).toString(16)} (${posHuman})`,
        );
        result.push("Scale: " + humanReadableScale(range[1] - range[0]));
        if (buf) {
            const len = buf.byteLength;
            const percent = Math.round((mouseAddr / len) * 100);
            const hrLen = humanReadableSizeFull(len);
            result.push(
                `Buffer: ${hrLen} (0x${len.toString(16)}), ${percent}% in`,
            );
        }
        if (members) {
            if (focusedMembers.length === 0) {
                result.push("Focused member: none");
            } else if (focusedMembers.length === 1) {
                const m = focusedMembers[0];
                const points =
                    m.ptr === undefined
                        ? ""
                        : ", points to 0x" + m.ptr.toString(16);
                const addrHex = m.addr.toString(16);
                result.push(
                    `Focused member (at 0x${addrHex}, len ${m.len}): ${m.name}${points}`,
                );
            } else if (focusedMembers > 1) {
                result.push("Warning: overlapping members!");
            }
        }
        return result;
    }
</script>

<div class="AddressSpace" style:width>
    <div class="status-lines">
        {#each status(mouseAddr, range, arrayBuffer, focusedMembers) as statusLine}
            <div>{statusLine}</div>
        {/each}
    </div>
    <canvas
        style:height
        bind:this={canvas}
        dir="ltr"
        on:mousemove={mouseMoved}
        on:mousewheel={wheelScrolled}
        on:click={mouseClicked}
    />
</div>

<svelte:window on:resize={onResize} bind:devicePixelRatio={dpr} />

<style>
    .AddressSpace {
        display: flex;
        flex-direction: column;
        font-family: monospace;
        box-sizing: border-box;
        border: 2px solid #0084ff55;
        border-radius: 8px;
    }

    .status-lines {
        padding: 10px;
    }

    canvas {
        padding: 0;
        display: block;
    }
</style>
