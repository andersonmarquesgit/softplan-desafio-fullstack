import { G_PROCESS_API } from './gprocess.api';
import { User } from './../model/user.model';
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'

@Injectable({
  providedIn: 'root'
})
export class ProcessService {

  constructor(private http: HttpClient) { }

  create(ocurrence: String){
    return this.http.post(`${G_PROCESS_API}/api/process`, ocurrence);
  }

  findById(id: string) {
    return this.http.get(`${G_PROCESS_API}/api/process/${id}`);
  }

  findAll(page: number, count:number) {
    return this.http.get(`${G_PROCESS_API}/api/process/${page}/${count}`);
  }

  findByParams(page: number, count:number, number:number, status:string){
    number = number == null ? 0 : number;
    status = status == null ? 'uninformed' : status;
    return this.http.get(`${G_PROCESS_API}/api/process/${page}/${count}/${number}/${status}`);
  }

  findByLegalOpinionIsNull(page: number, count:number, legalOpinionIsNull:boolean){
    legalOpinionIsNull = legalOpinionIsNull == null ? false : legalOpinionIsNull;
    return this.http.get(`${G_PROCESS_API}/api/process/${page}/${count}/${legalOpinionIsNull}`);
  }

  assignUser(id:string, assignUsers:Array<string>){
    return this.http.put(`${G_PROCESS_API}/api/process`, assignUsers);
  }
}
