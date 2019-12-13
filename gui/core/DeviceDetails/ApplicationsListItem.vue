<template>
                <li class="application-list-item">
                    <router-link class="router-link" v-bind:to="'/device/' + device.id + '/application/' + application.identifier">
                        {{ application.name }}
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
