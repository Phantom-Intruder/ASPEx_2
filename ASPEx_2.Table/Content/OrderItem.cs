/*----------------------------------------------------------------------------------------
* Page   : OrderItem
* File   : OrderItem.cs
* Author : Volume RADA Generator (Version 6.1)
* Date   : 8/23/2017
* Comment: Created by Author
* --------------------------------------------------------------------------------------*/

/*---------------------------------Version Control---------------------------------------
 *
 * DATE						 WHO                ACTION
 * 8/23/2017  Volume RADA Generator (Version 6.1)	Created
 *
 *-------------------------------End Version Control-------------------------------------*/

using System;
using System.Data;
using System.Collections;
using System.Configuration;
using System.Collections.Generic;

namespace ASPEx_table
{
	/// <summary>
	/// This is the class to define the table OrderItem
	/// </summary>

	public class OrderItem : Object, IComparable
	{

		#region Column Fields

		// V2Generator: Section Start : Database Column Field Names
		/// <summary>
		/// No information available for ID
		/// </summary>
		protected const string Field_ID																		 = "ID";
		/// <summary>
		/// No information available for OrderID
		/// </summary>
		protected const string Field_order_id  																 = "order_id";
		/// <summary>
		/// No information available for ProductID
		/// </summary>
		protected const string Field_product_id																 = "product_id";
		/// <summary>
		/// No information available for Quantity
		/// </summary>
		protected const string Field_quantity  																 = "quantity";
		/// <summary>
		/// No information available for UnitCost
		/// </summary>
		protected const string Field_unit_cost 																 = "unit_cost";
		/// <summary>
		/// No information available for Subtotal
		/// </summary>
		protected const string Field_subtotal  																 = "subtotal";
		// V2Generator: Section End :Database Column Field Names
		#endregion

		#region Protected Fields

		// V2Generator: Section Start : Protected fields section
		/// <summary>
		/// No information available for ID
		/// </summary>
		protected int 		m_ID										 = -1;
		/// <summary>
		/// No information available for OrderID
		/// </summary>
		protected int 		m_OrderID   								 = -1;
		/// <summary>
		/// No information available for ProductID
		/// </summary>
		protected int 		m_ProductID 								 = -1;
		/// <summary>
		/// No information available for Quantity
		/// </summary>
		protected int 		m_Quantity  								 = -1;
		/// <summary>
		/// No information available for UnitCost
		/// </summary>
		protected decimal 	m_UnitCost  								 = -1;
		/// <summary>
		/// No information available for Subtotal
		/// </summary>
		protected decimal 	m_Subtotal  								 = -1;
		// V2Generator: Section End :Protected fields section
		#endregion

		#region List Item

		// V2Generator: Section Start : List Item Attributes
		// V2Generator: Section End :List Item Attributes
		#endregion

		#region Constructors

		/// <summary>
		/// Creates a new OrderItem object
		/// </summary>
		/// <param name="ID">No information available for ID</param>
		/// <param name="OrderID">No information available for OrderID</param>
		/// <param name="ProductID">No information available for ProductID</param>
		/// <param name="Quantity">No information available for Quantity</param>
		/// <param name="UnitCost">No information available for UnitCost</param>
		/// <param name="Subtotal">No information available for Subtotal</param>
		/// <returns></returns>
		// V2Generator: Section Start : Constructor using all the fields
		protected OrderItem (
			int ID,
			int OrderID,
			int ProductID,
			int Quantity,
			decimal UnitCost,
			decimal Subtotal)
		{
			// V2Generator: Body Start
			this.m_ID   								 = ID;
			this.m_OrderID  							 = OrderID;
			this.m_ProductID							 = ProductID;
			this.m_Quantity 							 = Quantity;
			this.m_UnitCost 							 = UnitCost;
			this.m_Subtotal 							 = Subtotal;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Constructor using all the fields

		/// <summary>
		/// Creates a new OrderItem object
		/// </summary>
		/// <param name="OrderID">No information available for OrderID</param>
		/// <param name="ProductID">No information available for ProductID</param>
		/// <param name="Quantity">No information available for Quantity</param>
		/// <param name="UnitCost">No information available for UnitCost</param>
		/// <param name="Subtotal">No information available for Subtotal</param>
		/// <returns></returns>
		// V2Generator: Section Start : Constructor for insert
		protected OrderItem (
			int OrderID,
			int ProductID,
			int Quantity,
			decimal UnitCost,
			decimal Subtotal)
		{
			// V2Generator: Body Start
			this.m_OrderID  						= OrderID;
			this.m_ProductID						= ProductID;
			this.m_Quantity 						= Quantity;
			this.m_UnitCost 						= UnitCost;
			this.m_Subtotal 						= Subtotal;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Constructor for insert

		#endregion

		#region Execute Create

		/// <summary>
		/// Creates a new OrderItem object based on the given record id from the database
		/// </summary>
		/// <param name="ID">No information available for ID</param>
		/// <returns>null or a new OrderItem object</returns>
		// V2Generator: Section Start : ExecuteCreate By ID
		public static OrderItem ExecuteCreate (int ID)
		{
			// V2Generator: Body Start
			OrderItem   				  result     = null;

			DataTable   				  dt  		  = ASPEx_sql.OrderItem.OrderItemGetByID(ID);

			if (dt.Rows.Count>0)
			{
				result									= Create(dt.Rows[0]);
			}

			return result;
			// V2Generator: Body End
		}
		// V2Generator: Section End :ExecuteCreate By ID

		/// <summary>
		/// Creates a new OrderItem object for inserting a new record into the database
		/// </summary>
		/// <param name="OrderID">No information available for OrderID</param>
		/// <param name="ProductID">No information available for ProductID</param>
		/// <param name="Quantity">No information available for Quantity</param>
		/// <param name="UnitCost">No information available for UnitCost</param>
		/// <param name="Subtotal">No information available for Subtotal</param>
		/// <returns>null or a new OrderItem object</returns>
		// V2Generator: Section Start : ExecuteCreate Insert
		public static OrderItem ExecuteCreate (
			int OrderID,
			int ProductID,
			int Quantity,
			decimal UnitCost,
			decimal Subtotal)
		{
			// V2Generator: Body Start
			OrderItem	result		= null;

			#region Validate the input parameter(s)

			#endregion

			result			= new OrderItem(OrderID, ProductID, Quantity, UnitCost, Subtotal);
			return result;
			// V2Generator: Body End
		}
		// V2Generator: Section End :ExecuteCreate Insert

		/// <summary>
		/// Creates a new OrderItem object
		/// </summary>
		/// <param name="row"></param>
		/// <returns>null or a new OrderItem object</returns>
		// V2Generator: Section Start : ExecuteCreate Row
		internal static OrderItem ExecuteCreate (DataRow row)
		{
			// V2Generator: Body Start
			return Create(row);
			// V2Generator: Body End
		}
		// V2Generator: Section End :ExecuteCreate Row

		#endregion

		#region Create

		/// <summary>
		/// Creates a new OrderItem object based on the given row obtained from the database. The row is from the table OrderItem.
		/// </summary>
		/// <param name="row"></param>
		/// <returns>null or a OrderItem object</returns>
		// V2Generator: Section Start : Create section
		private static OrderItem Create (DataRow row)
		{
			// V2Generator: Body Start
			OrderItem  result  			 = null;
			
			int 	   ID  				 = -1;
			int 	   OrderID 			 = -1;
			int 	   ProductID   		 = -1;
			int 	   Quantity			 = -1;
			decimal    UnitCost			 = -1;
			decimal    Subtotal			 = -1;

			#region get the values
			ID  							 = (int) row[Field_ID];
			if (row[Field_order_id]!=System.DBNull.Value)
			{
				OrderID 					 = (int) row[Field_order_id];
			}
			if (row[Field_product_id]!=System.DBNull.Value)
			{
				ProductID   				 = (int) row[Field_product_id];
			}
			if (row[Field_quantity]!=System.DBNull.Value)
			{
				Quantity					 = (int) row[Field_quantity];
			}
			if (row[Field_unit_cost]!=System.DBNull.Value)
			{
				UnitCost					 = (decimal) row[Field_unit_cost];
			}
			if (row[Field_subtotal]!=System.DBNull.Value)
			{
				Subtotal					 = (decimal) row[Field_subtotal];
			}
			#endregion
			result  						 = new OrderItem(ID, OrderID, ProductID, Quantity, UnitCost, Subtotal);

			return result;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Create section

		#endregion

		#region Relation

		/// <summary>
		/// Creates relationship between OrderItem and primary tables
		/// </summary>
		/// <returns>null or a OrderItemDataTable</returns>
		// V2Generator: Section Start : Relations
		protected static DataTable  AddRelation ()
		{
			// V2Generator: Body Start
		return null;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Relations

		#endregion

		#region List Methods

		/// <summary>
		/// Lists all the records from the database
		/// </summary>
		/// <returns></returns>
		// V2Generator: Section Start : List all
		public static List<OrderItem> List ()
		{
			// V2Generator: Body Start
			List<OrderItem>			list				= new List<OrderItem>();
			DataTable			dt					= ASPEx_sql.OrderItem.OrderItemList();

			for (int i=0; i<dt.Rows.Count; i++)
			{
				OrderItem   	result				= Create(dt.Rows[i]);
				if (result!=null)
				{
					list.Add(result);
				}
			}

			list.Sort();

			return list;
			// V2Generator: Body End
		}
		// V2Generator: Section End :List all


		#endregion

		#region DB Methods

		/// <summary>
		/// Deletes the object record from the database (Does not act as a destructor)
		/// </summary>
		/// <returns></returns>
		// V2Generator: Section Start : Delete
		public void Delete ()
		{
			// V2Generator: Body Start
			ASPEx_sql.OrderItem.OrderItemDelete (this.m_ID);
			// V2Generator: Body End
		}
		// V2Generator: Section End :Delete

		/// <summary>
		/// Updates the object members and the corresponding row in the database.
		/// </summary>
		/// <param name="OrderID">No information available for OrderID</param>
		/// <param name="ProductID">No information available for ProductID</param>
		/// <param name="Quantity">No information available for Quantity</param>
		/// <param name="UnitCost">No information available for UnitCost</param>
		/// <param name="Subtotal">No information available for Subtotal</param>
		/// <returns></returns>
		// V2Generator: Section Start : Update
		protected void Update (
			int OrderID,
			int ProductID,
			int Quantity,
			decimal UnitCost,
			decimal Subtotal)
		{
			// V2Generator: Body Start
			ASPEx_sql.OrderItem.OrderItemUpdate (ID, OrderID, ProductID, Quantity, UnitCost, Subtotal);

			this.m_OrderID  			  = OrderID;
			this.m_ProductID			  = ProductID;
			this.m_Quantity 			  = Quantity;
			this.m_UnitCost 			  = UnitCost;
			this.m_Subtotal 			  = Subtotal;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Update

		/// <summary>
		/// Inserts a new record into the database, and updates the identity field in this object.
		/// </summary>
		/// <returns></returns>
		// V2Generator: Section Start : Insert
		public void Insert ()
		{
			// V2Generator: Body Start
			this.m_ID			= ASPEx_sql.OrderItem.OrderItemInsert (this.m_OrderID, this.m_ProductID, this.m_Quantity, this.m_UnitCost, this.m_Subtotal);
			// V2Generator: Body End
		}
		// V2Generator: Section End :Insert

		#endregion

		#region Compare

		/// <summary>
		/// Compares the current OrderItem object with the given OrderItem object
		/// </summary>
		/// <param name="row">The OrderItem object to compare with</param>
		/// <returns>The compared difference between the OrderItem objects</returns>
		// V2Generator: Section Start : CompareTo
		public int CompareTo (object row)
		{
			// V2Generator: Body Start
			if(row is OrderItem)
			{
				OrderItem temp = (OrderItem) row;
				return ID.CompareTo(temp.ID);
			}
			else
			{
				throw new System.ArgumentException("object is not a OrderItem");
			}
			// V2Generator: Body End
		}
		// V2Generator: Section End :CompareTo

		/// <summary>
		/// Get HashCode
		/// </summary>
		/// <returns>HashCode</returns>
		// V2Generator: Section Start : GetHashCode
		public override int  GetHashCode ()
		{
			// V2Generator: Body Start
		return base.GetHashCode ();
			// V2Generator: Body End
		}
		// V2Generator: Section End :GetHashCode

		/// <summary>
		/// Equals from Object class
		/// </summary>
		/// <param name="obj">The OrderItem object to compare with</param>
		/// <returns>True if equal else false</returns>
		// V2Generator: Section Start : Equals
		public override bool  Equals (object obj)
		{
			// V2Generator: Body Start
		bool  result     = false;
		if (this.ID ==((OrderItem)obj).ID)
		{
			result     = true;
		}
		 return result;
			// V2Generator: Body End
		}
		// V2Generator: Section End :Equals

		#endregion

		#region Assessors

		// V2Generator: Section Start : Assessors section
		/// <summary>
		/// No information available for ID
		/// </summary>
		public int ID
		{
			get{return this.m_ID;}
		}
		/// <summary>
		/// No information available for OrderID
		/// </summary>
		public int OrderID
		{
			get{return this.m_OrderID;}
		}
		/// <summary>
		/// No information available for ProductID
		/// </summary>
		public int ProductID
		{
			get{return this.m_ProductID;}
		}
		/// <summary>
		/// No information available for Quantity
		/// </summary>
		public int Quantity
		{
			get{return this.m_Quantity;}
		}
		/// <summary>
		/// No information available for UnitCost
		/// </summary>
		public decimal UnitCost
		{
			get{return this.m_UnitCost;}
		}
		/// <summary>
		/// No information available for Subtotal
		/// </summary>
		public decimal Subtotal
		{
			get{return this.m_Subtotal;}
		}
		// V2Generator: Section End :Assessors section
		// V2Generator: Section Start : List Item Assessor
		// V2Generator: Section End :List Item Assessor
		#endregion

	}

}

