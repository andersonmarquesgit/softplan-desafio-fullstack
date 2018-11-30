import { G_PROCESS_API } from './gprocess.api';
import { User } from './../model/user.model';
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
 
@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(private http: HttpClient) { }

  login(user: User){
    return this.http.post(`${G_PROCESS_API}/api/auth`, user);
  }

  createOrUpdate(user: User){
    if(user.id != null && user.id != ''){
      return this.http.put(`${G_PROCESS_API}/api/user`, user);
    } else {
      return this.http.post(`${G_PROCESS_API}/api/user`, user);
    }
  }

  findAll(page: number, count:number) {
    return this.http.get(`${G_PROCESS_API}/api/user/${page}/${count}`);
  }

  findById(id: string) {
    return this.http.get(`${G_PROCESS_API}/api/user/${id}`);
  }

  delete(id: string){
    return this.http.delete(`${G_PROCESS_API}/api/user/${id}`);
  }
}
