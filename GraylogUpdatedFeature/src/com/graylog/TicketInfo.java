  package com.graylog;

public class TicketInfo {
   private String actionType;
   private String id;
   private String statusOrLabel;
   private String label_status;

   public TicketInfo(String actionType, String id, String statusOrLabel, String label_status){
      this.actionType = actionType;
      this.id = id;
      this.statusOrLabel = statusOrLabel;
      this.label_status= label_status;
      }

   public String getActionType(){
      return this.actionType; 
   }

   public void setActionType(String actionType) {
      this.actionType = actionType;
   }

   public String getId() {
      return this.id;
   }

   public void setId(String id) {
      this.id = id;
   }

   public String getStatusOrLabel() {
      return this.statusOrLabel;
   }

   public void setStatusOrLabel(String statusOrLabel) {
      this.statusOrLabel = statusOrLabel;
   }

   public String getLabel_status() {
      return this.label_status;
   }

   public void setLabel_status(String label_status) {
      this.label_status = label_status;
   }

   public String toString() {
      return "TicketInfo{actionType='" + this.actionType + '\'' + ", id='" + this.id + '\'' + ", statusOrLabel='" + this.statusOrLabel + '\'' + ", label_status='" + this.label_status + '\'' + '}';
   }
}