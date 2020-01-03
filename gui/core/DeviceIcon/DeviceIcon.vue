<template>
    <CellphoneAndroidIcon v-if="type === 'usb'" :size=size />
    <WebIcon v-else-if="type === 'remote'" :size=size />
    <DesktopClassicIcon v-else-if="type === 'local'" :size=size />
    <LibraryIcon v-else-if="type === 'library'" :size=size />
    <CellphoneIcon v-else :size=size />
</template>

<script>
import CellphoneAndroidIcon from 'vue-material-design-icons/CellphoneAndroid.vue';
import WebIcon from 'vue-material-design-icons/Web.vue';
import DesktopClassicIcon from 'vue-material-design-icons/DesktopClassic.vue';
import CellphoneIcon from 'vue-material-design-icons/Cellphone.vue';
import LibraryIcon from 'vue-material-design-icons/Library.vue';

export default {
    name: "device-icon",
    props: ['type', 'size'],
    components: {
        CellphoneAndroidIcon,
        CellphoneIcon,
        WebIcon,
        DesktopClassicIcon,
        LibraryIcon
  }
}
</script>

<style scoped>
</style>