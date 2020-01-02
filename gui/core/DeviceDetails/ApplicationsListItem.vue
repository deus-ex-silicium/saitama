<template>
  <li class="application-list-item">
      <router-link class="router-link" :to="'/device/' + device.id + '/application/' + application.identifier">
          {{ application.name }} {{ application.hasOwnProperty('pid')? "("+application.pid+")": "" }}
      </router-link>
  </li>
</template>

<script>
export default {
  name: 'applications-list-item',
  props: ['application', 'device'],
}
</script>

<style>

</style>
