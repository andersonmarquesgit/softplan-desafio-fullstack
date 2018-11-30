import { User } from "./user.model";

export class Process {
    constructor(
        public id: string,
        public number: number,
        public ocurrence: string,
        public legalOpnion: string,
        public createAt:Date,
        public updateAt: Date,
        public status: string,
        public usersAssigned: Array<User>
    ){}
}