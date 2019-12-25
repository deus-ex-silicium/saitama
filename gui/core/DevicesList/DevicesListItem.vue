<template>
  <li class="devices-list-item">
    <router-link class="router-link" v-bind:to="'/device/' + device.id + '/'">
      <device-icon :type=device.type size="36" />
      <br>
      {{ device.name }}
    </router-link>
  </li>
</template>

<script>
import DeviceIcon from '../DeviceIcon/DeviceIcon.vue'

export default {
  name: "devices-list-item",
  props: ['device'],
  components: {
    DeviceIcon
  }
};
</script>

<style scoped>
</style>
