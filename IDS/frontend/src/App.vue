<template>
    <v-app>
        <v-toolbar app color="indigo" dar>
            <v-toolbar-title>SSH IDS Dashboard</v-toolbar-title>
        </v-toolbar>
        <v-content>
            <v-container>
                <suspicious-table></suspicious-table>
            </v-container>
        </v-content>
    </v-app>
</template>

<script>
import SuspiciousTable from './components/SuspiciousTable.vue'

export default {
    components: {
        SuspiciousTable
    }
}
</script>
