<script>
    import { onMount } from "svelte";
    import parser from "$lib/parser";
    import AddressSpace from "./AddressSpace.svelte";

    let elfBuffer;
    let errorMessage;
    let members, areas;

    function onLoaded(buf) {
        elfBuffer = buf;
        const result = parser(buf);
        if (typeof result === "string") {
            errorMessage = result;
        } else {
            members = result.members;
            areas = result.areas;
        }
    }

    onMount(() => {
        fetch("/bin/test")
            .then((r) => r.arrayBuffer())
            .then((buf) => onLoaded(buf));
    });
</script>

{#if errorMessage}
    <code style="white-space: pre;">{errorMessage}</code>
{/if}

<AddressSpace arrayBuffer={elfBuffer} {members} {areas} />
