<template>
    <v-card>
        <v-card-title>
            <span class="headline">Suspicious SSH Attempts</span>
        </v-card-title>
        <v-card-text>
            <v-text-field v-model="startDate" label="Start Date (YYYY-MM-DDTHH:MM:SS)" clearable></v-text-field>
            <v-text-filed v-model="endDate" label="End Date (YYYY-MM-DDTHH:MM:SS)" clearable></v-text-filed>
            <v-btn color="primary" @click="fetchData">Fetch</v-btn>

            <v-data-table :headers="headers" :items="items" class="elevation-1" :items-per-page="10">
                <template v-slot:item.start_time="{ item }">
                    {{ new Date(item.start_time).toLocaleString() }}
                </template>
                <template v-slot:item.end_time="{ item }">
                    {{ new Date(item.end_time).toLocaleString() }}
                </template>
            </v-data-table>
        </v-card-text>
    </v-card>
</template>

<script>
import axios from 'axios'

export default {
    data() {
        return {
            headers: [
                { text: 'IP', value: 'ip' },
                { text: 'Count', value: 'count' },
                { text: 'Start Time', value: 'start_time' },
                { text: 'End Time', value: 'end_time' }
            ],
            items: [],
            startDate: '',
            endDate: ''
        }
    },
    methods: {
        async fetchData() {
            const params = {}
            if (this.startDate) params.start = this.startDate
            if (this.endDate) params.end = this.endDate

            const resp = await axios.get('http://localhost:8000/suspicious', { params })
            this.items = resp.data
        }
    },
    mounted() {
        this.fetchData()
    }
}
</script>
