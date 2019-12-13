<template>
  <li class="devices-list-item">
    <router-link class="router-link" v-bind:to="'/device/' + device.id + '/'">
      <CellphoneAndroidIcon v-if="device.type === 'usb'" :size="36" />
      <CellphoneIcon v-else :size="36" />
      <br>
      {{ device.name }}
    </router-link>
  </li>
</template>

<script>
import CellphoneAndroidIcon from 'vue-material-design-icons/CellphoneAndroid.vue';
import CellphoneIcon from 'vue-material-design-icons/Cellphone.vue';

export default {
  name: "devices-list-item",
  components: {
    CellphoneAndroidIcon,
    CellphoneIcon
  },
  props: ['device'],
};
</script>

<style>
</style>
